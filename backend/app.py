"""
netviz – FastAPI application entry point.

Responsibilities:
    * Bootstrap all backend services (capture, geo, DNS, traceroute, ...).
    * Expose HTTP endpoints and a WebSocket channel for the frontend.
    * Broadcast capture / traceroute / ignore events to all connected clients.
    * Serve the static frontend from ../frontend.

Run directly with `python app.py` or via uvicorn.
"""

import asyncio
import json
import threading
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from config import (
    IFACE, HOST, PORT,
    IDLE_TIMEOUT, REVIVE_THRESHOLD, SWEEP_INTERVAL, TICK_INTERVAL,
    GEO_DB_PATH, LOCAL_GEO,
    EXTERNAL_IP_REFRESH, USE_EXTERNAL_IP,
    DNS_ENABLED, DNS_WORKERS,
    TRACE_CACHE_FILE, TRACE_CACHE_TTL, TRACE_METHOD, TRACE_SYS_CMD,
    TRACE_MAX_HOPS, TRACE_HOP_TIMEOUT,
    TRACE_MAX_CONCURRENT, TRACE_MIN_INTERVAL, TRACE_DEBUG,
    BASEMAP_URL_TEMPLATE, BASEMAP_API_KEY, BASEMAP_ATTRIBUTION,
    BASEMAP_SUBDOMAINS, BASEMAP_MAX_ZOOM,
    MAP_DEFAULT_LAT, MAP_DEFAULT_LON, MAP_DEFAULT_ZOOM,
)
from capture import CaptureEngine
from flows import FlowTable
from geo import GeoResolver
from external_ip import ExternalIPResolver
from dns import DNSResolver
from connection_log import ConnectionLogger
from ignore import IgnoreSet
from traceroute import TracerouteService

# ─── Paths ────────────────────────────────────────────────────────────────
BASE_DIR      = Path(__file__).parent
FRONTEND_DIR  = BASE_DIR.parent / "frontend"
LOG_DIR       = BASE_DIR / "logs"
TRACE_CACHE_PATH = str(BASE_DIR / TRACE_CACHE_FILE)

# ─── Service singletons ───────────────────────────────────────────────────
# These are created once at import time. The capture engine and the
# traceroute service are instantiated inside `lifespan` because they need
# a running event loop.
external = (
    ExternalIPResolver(refresh_interval=EXTERNAL_IP_REFRESH)
    if USE_EXTERNAL_IP else None
)
if external:
    external.refresh(force=True)

geo = GeoResolver(
    GEO_DB_PATH,
    local_geo=LOCAL_GEO,
    external_resolver=external,
)

dns      = DNSResolver(workers=DNS_WORKERS) if DNS_ENABLED else None
ignore   = IgnoreSet()
conn_log = ConnectionLogger(str(LOG_DIR))

flows = FlowTable(idle_timeout=IDLE_TIMEOUT, revive_threshold=REVIVE_THRESHOLD)

clients: set[WebSocket] = set()
capture_engine: CaptureEngine | None = None
traceroute_svc: TracerouteService | None = None


# ─── Broadcast helpers ────────────────────────────────────────────────────
async def broadcast(msg: dict) -> None:
    """
    Send `msg` (JSON-encoded) to every connected WebSocket client.

    Dead sockets are pruned silently.
    """
    if not clients:
        return
    data = json.dumps(msg)
    dead = []
    for ws in list(clients):
        try:
            await ws.send_text(data)
        except Exception:
            dead.append(ws)
    for ws in dead:
        clients.discard(ws)


async def on_traceroute_result(result: dict) -> None:
    """Callback invoked by TracerouteService when a trace completes."""
    await broadcast({
        "type":   "traceroute_result",
        "target": result["target"],
        "hops":   result["hops"],
    })


# ─── Background tasks ─────────────────────────────────────────────────────
async def sweeper_task() -> None:
    """Periodically remove idle flows and notify clients with `flow_down`."""
    while True:
        await asyncio.sleep(SWEEP_INTERVAL)
        for key in flows.sweep():
            await broadcast({"type": "flow_down", "key": list(key)})


async def ticker_task() -> None:
    """Push a snapshot of active flows to clients every TICK_INTERVAL seconds."""
    while True:
        await asyncio.sleep(TICK_INTERVAL)
        if not clients:
            continue

        snap = flows.snapshot(active_window=2.0)

        # Enrich each flow with the newest hostname from the DNS cache.
        if dns is not None:
            for f in snap:
                for side in ("src", "dst"):
                    ip = f[side]["ip"]
                    hn = dns.peek(ip)
                    if hn is not None and f[side].get("hostname") != hn:
                        f[side]["hostname"] = hn

        await broadcast({"type": "tick", "flows": snap})


async def external_ip_task() -> None:
    """Re-detect the public IP periodically; clear the geo cache on change."""
    if external is None:
        return
    while True:
        await asyncio.sleep(EXTERNAL_IP_REFRESH)
        old    = external.get()
        old_ip = old["ip"] if old else None
        new    = external.refresh(force=True)
        if new and new["ip"] != old_ip:
            print(f"[external-ip] changed: {old_ip} → {new['ip']}")
            with geo._lock:
                geo._cache.clear()
            await broadcast({"type": "local_ip_changed", "external": new})


async def pump_events() -> None:
    """
    Forward events emitted by the capture thread into the asyncio loop,
    handling the special `trace_request` event inline.
    """
    assert capture_engine is not None
    while True:
        event = await capture_engine.queue.get()
        t = event.get("type")

        if t == "trace_request":
            if traceroute_svc is not None:
                target = event.get("target")
                if target and traceroute_svc.request(target):
                    print(f"[traceroute] queued {target}")
                    await broadcast({"type": "traceroute_pending", "target": target})
            continue

        await broadcast(event)


# ─── Lifespan ─────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Start / stop long-running services around the FastAPI application.

    On startup:   spawn the capture thread and all background tasks.
    On shutdown:  cancel background tasks (capture thread is a daemon).
    """
    global capture_engine, traceroute_svc
    loop = asyncio.get_running_loop()

    # Traceroute service
    traceroute_svc = TracerouteService(
        geo=geo,
        dns=dns,
        on_result=on_traceroute_result,
        cache_path=TRACE_CACHE_PATH,
        cache_ttl=TRACE_CACHE_TTL,
        method=TRACE_METHOD,
        sys_cmd=TRACE_SYS_CMD,
        max_concurrent=TRACE_MAX_CONCURRENT,
        min_interval=TRACE_MIN_INTERVAL,
        max_hops=TRACE_MAX_HOPS,
        hop_timeout=TRACE_HOP_TIMEOUT,
        debug=TRACE_DEBUG,
    )

    # Packet capture engine (runs in a dedicated thread)
    capture_engine = CaptureEngine(IFACE, geo, flows, dns, ignore, conn_log, loop)
    threading.Thread(target=capture_engine.start, daemon=True).start()

    tasks = [
        asyncio.create_task(sweeper_task()),
        asyncio.create_task(ticker_task()),
        asyncio.create_task(pump_events()),
        asyncio.create_task(external_ip_task()),
        asyncio.create_task(traceroute_svc.runner()),
    ]
    try:
        yield
    finally:
        for task in tasks:
            task.cancel()


app = FastAPI(lifespan=lifespan, title="netviz", version="1.0.0")
app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")


# ─── HTTP endpoints ───────────────────────────────────────────────────────
@app.get("/")
async def index():
    """Serve the single-page frontend."""
    return FileResponse(FRONTEND_DIR / "index.html")


@app.get("/api/config")
async def api_config():
    """
    Expose frontend-relevant configuration.

    The basemap API key is delivered here, so the frontend never hard-codes
    any credential or provider URL.
    """
    return {
        "basemap": {
            "urlTemplate": BASEMAP_URL_TEMPLATE,
            "apiKey":      BASEMAP_API_KEY,
            "attribution": BASEMAP_ATTRIBUTION,
            "subdomains":  BASEMAP_SUBDOMAINS,
            "maxZoom":     BASEMAP_MAX_ZOOM,
        },
        "map": {
            "defaultLat":  MAP_DEFAULT_LAT,
            "defaultLon":  MAP_DEFAULT_LON,
            "defaultZoom": MAP_DEFAULT_ZOOM,
        },
        "tickInterval": TICK_INTERVAL,
    }


@app.get("/api/me")
async def me():
    """Return the detected public IP, fallback geo and current ignore list."""
    return {
        "external":           external.get() if external else None,
        "local_geo_fallback": LOCAL_GEO,
        "ignored":            [list(k) for k in ignore.all()],
    }


@app.get("/api/traceroute/{ip}")
async def traceroute_endpoint(ip: str):
    """
    Request a traceroute for `ip`.

    Returns the cached result if available, otherwise queues a new trace and
    returns `{"pending": True}`. The actual result is delivered over the
    WebSocket as `traceroute_result`.
    """
    if traceroute_svc is None:
        return {"target": ip, "hops": [], "error": "service unavailable"}
    cached = traceroute_svc.get_cached(ip)
    if cached:
        return cached
    traceroute_svc.request(ip)
    return {"target": ip, "hops": [], "pending": True}


@app.get("/api/test-traceroute/{ip}")
async def test_traceroute(ip: str):
    """
    Debug endpoint – runs both traceroute methods synchronously and returns
    their results. Useful when troubleshooting system vs scapy behaviour.
    """
    import time
    loop = asyncio.get_running_loop()
    out  = {}

    if traceroute_svc is None:
        return {"error": "service not initialized"}

    t0 = time.time()
    try:
        hops = await loop.run_in_executor(None, traceroute_svc._trace_system, ip)
        out["system"] = {
            "hops":   hops,
            "count":  len(hops),
            "time_s": round(time.time() - t0, 2),
        }
    except Exception as e:
        out["system"] = {"error": f"{type(e).__name__}: {e}"}

    t1 = time.time()
    try:
        hops = await loop.run_in_executor(None, traceroute_svc._trace_scapy, ip)
        out["scapy"] = {
            "hops":   hops,
            "count":  len(hops),
            "time_s": round(time.time() - t1, 2),
        }
    except Exception as e:
        out["scapy"] = {"error": f"{type(e).__name__}: {e}"}

    return out


# ─── WebSocket ────────────────────────────────────────────────────────────
async def handle_client_message(msg: dict) -> None:
    """
    Dispatch a single JSON message received from a WebSocket client.

    Supported message types:
        * `set_ignore`   – toggle ignoring a (src_ip, dst_ip) pair
        * `request_trace`– request a traceroute for a target IP
    """
    t = msg.get("type")

    if t == "set_ignore":
        key = msg.get("conn_key")
        if not isinstance(key, list) or len(key) != 2:
            return
        src_ip, dst_ip = key[0], key[1]
        want_ignore    = bool(msg.get("ignored"))

        if want_ignore:
            changed = ignore.add(src_ip, dst_ip)
            removed = flows.close_by_connection(src_ip, dst_ip)
            for k in removed:
                await broadcast({"type": "flow_down", "key": list(k)})
            if changed:
                print(f"[ignore] + {src_ip} → {dst_ip}")
        else:
            changed = ignore.remove(src_ip, dst_ip)
            if changed:
                print(f"[ignore] - {src_ip} → {dst_ip}")

        await broadcast({
            "type":     "ignore_changed",
            "conn_key": [src_ip, dst_ip],
            "ignored":  want_ignore,
        })
        return

    if t == "request_trace":
        target = msg.get("target")
        if not target or traceroute_svc is None:
            return
        cached = traceroute_svc.get_cached(target)
        if cached:
            await broadcast({
                "type":   "traceroute_result",
                "target": cached["target"],
                "hops":   cached["hops"],
            })
            return
        if traceroute_svc.request(target):
            await broadcast({"type": "traceroute_pending", "target": target})
        return


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    """
    Main WebSocket channel.

    On connect the client receives an `init` message with the current flow
    snapshot, the detected public IP, the ignore list and cached traces.
    After that, all state changes are delivered as individual events.
    """
    await ws.accept()
    clients.add(ws)
    try:
        await ws.send_text(json.dumps({
            "type":     "init",
            "flows":    flows.snapshot(active_window=IDLE_TIMEOUT),
            "external": external.get() if external else None,
            "ignored":  [list(k) for k in ignore.all()],
            "traces":   traceroute_svc.cached_all() if traceroute_svc else [],
        }))
        while True:
            raw = await ws.receive_text()
            try:
                msg = json.loads(raw)
            except Exception:
                continue
            try:
                await handle_client_message(msg)
            except Exception as e:
                print(f"[ws] handler error: {e}")
    except WebSocketDisconnect:
        pass
    finally:
        clients.discard(ws)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=HOST, port=PORT, log_level="info")
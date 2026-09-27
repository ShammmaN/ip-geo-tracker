"""
netviz – traceroute service.

Performs traceroute on demand with either the system `traceroute` binary or
scapy's implementation, enriches every hop with geolocation + reverse DNS,
and caches results to disk.
"""

import asyncio
import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path

from scapy.all import traceroute as scapy_traceroute


# Regex for typical traceroute output lines, e.g.:
#   3  8.8.8.8  15.234 ms  15.345 ms  15.456 ms
#   1  192.168.0.1  4.204 ms *  142.948 ms
_HOP_RE = re.compile(r"^\s*(\d+)\s+([0-9a-fA-F\.:]+)\s+([\d\.]+)\s*ms")


class TracerouteService:
    """
    Asynchronous traceroute service with queueing, caching and rate limiting.

    Parameters
    ----------
    geo            : GeoResolver instance
    dns            : DNSResolver instance (or None)
    on_result      : async callback invoked with each completed trace
    cache_path     : JSON file for persisting traces (None disables disk cache)
    cache_ttl      : cache lifetime in seconds (None = forever)
    method         : "auto" | "system" | "scapy"
    sys_cmd        : system binary name ("traceroute" or "tracepath")
    max_concurrent : max simultaneous traceroute jobs
    min_interval   : minimum delay between successive trace starts (s)
    queue_size     : request queue capacity
    max_hops       : maximum TTL to probe
    hop_timeout    : per-hop timeout in seconds
    debug          : print verbose logs
    """

    def __init__(
        self,
        geo,
        dns,
        on_result,
        cache_path: str | None = None,
        cache_ttl: int | None = None,
        method: str = "auto",
        sys_cmd: str = "traceroute",
        max_concurrent: int = 2,
        min_interval: float = 2.0,
        queue_size: int = 50,
        max_hops: int = 20,
        hop_timeout: float = 1.5,
        debug: bool = True,
    ):
        self.geo            = geo
        self.dns            = dns
        self.on_result      = on_result
        self.cache_path     = cache_path
        self.cache_ttl      = cache_ttl
        self.method         = method
        self.sys_cmd        = sys_cmd
        self.max_concurrent = max_concurrent
        self.min_interval   = min_interval
        self.max_hops       = max_hops
        self.hop_timeout    = hop_timeout
        self.debug          = debug

        self._cache: dict[str, dict]  = {}
        self._inflight: set[str]      = set()
        self._queue: asyncio.Queue    = asyncio.Queue(maxsize=queue_size)
        self._last_start: float       = 0.0
        self._sem                     = asyncio.Semaphore(max_concurrent)

        self._sys_available = bool(shutil.which(self.sys_cmd))
        if debug:
            print(f"[traceroute] method={method} sys_cmd={sys_cmd} "
                  f"available={self._sys_available}")
            if not self._sys_available:
                print(f"[traceroute] WARNING: '{sys_cmd}' not in PATH – "
                      f"scapy fallback will be used")

        self._load_cache()

    # ─── Logging ──────────────────────────────────────────────────────────
    def _log(self, *args) -> None:
        """Print a debug message if `debug` is enabled."""
        if self.debug:
            print("[traceroute]", *args)

    # ─── Persistence ──────────────────────────────────────────────────────
    def _load_cache(self) -> None:
        """Load previously saved traces from the cache file."""
        if not self.cache_path:
            return
        p = Path(self.cache_path)
        if not p.exists() or p.stat().st_size == 0:
            self._log(f"cache file empty or missing: {self.cache_path}")
            return
        try:
            with open(p, "r", encoding="utf-8") as f:
                data = json.load(f)
            entries = data.get("entries", {})
            loaded  = 0
            now     = time.time()
            for k, v in entries.items():
                if not isinstance(v, dict) or "ts" not in v or "result" not in v:
                    continue
                if self.cache_ttl is not None and (now - v["ts"]) >= self.cache_ttl:
                    continue
                self._cache[k] = v
                loaded += 1
            self._log(f"loaded {loaded} cached traces from {self.cache_path}")
        except Exception as e:
            self._log(f"cache load failed: {e}")

    def _save_cache(self) -> None:
        """Atomically persist the in-memory cache to disk."""
        if not self.cache_path:
            return
        try:
            tmp = self.cache_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(
                    {"saved_at": time.time(), "entries": self._cache},
                    f, indent=2,
                )
            os.replace(tmp, self.cache_path)
            self._log(f"cache saved ({len(self._cache)} entries) → {self.cache_path}")
        except Exception as e:
            self._log(f"cache save failed: {e}")

    # ─── Public API ───────────────────────────────────────────────────────
    def get_cached(self, target: str) -> dict | None:
        """Return a valid cached trace for `target`, or None."""
        entry = self._cache.get(target)
        if not entry:
            return None
        if self.cache_ttl is not None and (time.time() - entry["ts"]) >= self.cache_ttl:
            return None
        return entry["result"]

    def has_cached(self, target: str) -> bool:
        """True if a valid cached trace exists for `target`."""
        return self.get_cached(target) is not None

    def cached_all(self) -> list[dict]:
        """Return every valid cached trace result."""
        now = time.time()
        out = []
        for e in self._cache.values():
            if self.cache_ttl is not None and (now - e["ts"]) >= self.cache_ttl:
                continue
            out.append(e["result"])
        return out

    def is_inflight(self, target: str) -> bool:
        """True if a trace for `target` is currently queued or running."""
        return target in self._inflight

    def request(self, target: str) -> bool:
        """
        Queue a trace for `target`.

        Returns True if the request was accepted, False if it was a
        duplicate, already cached, or the queue was full.
        """
        if not target:
            return False
        if target in self._inflight:
            return False
        if self.get_cached(target):
            return False
        try:
            self._queue.put_nowait(target)
            self._inflight.add(target)
            self._log(f"queued {target}")
            return True
        except asyncio.QueueFull:
            self._log(f"queue full, dropped {target}")
            return False

    # ─── Runner loop ──────────────────────────────────────────────────────
    async def runner(self) -> None:
        """
        Consume the queue and dispatch worker tasks.

        Enforces `min_interval` between successive trace starts.
        """
        self._log("runner started")
        while True:
            target = await self._queue.get()
            now    = time.time()
            delta  = now - self._last_start
            if delta < self.min_interval:
                await asyncio.sleep(self.min_interval - delta)
            self._last_start = time.time()
            asyncio.create_task(self._worker(target))

    async def _worker(self, target: str) -> None:
        """Run a single trace for `target`, cache it and notify the caller."""
        self._log(f"worker start → {target}")
        t0 = time.time()
        try:
            async with self._sem:
                hops = await self._do_trace(target)
            dt = time.time() - t0
            self._log(f"worker done  → {target}: {len(hops)} hops in {dt:.1f}s")

            if hops:
                result = {"target": target, "hops": hops, "ts": time.time()}
                self._cache[target] = {"ts": time.time(), "result": result}
                self._save_cache()
                await self.on_result(result)
            else:
                self._log(f"empty result for {target} – not caching")
        except Exception as e:
            self._log(f"worker error → {target}: {type(e).__name__}: {e}")
        finally:
            self._inflight.discard(target)

    # ─── Orchestration ────────────────────────────────────────────────────
    async def _do_trace(self, target: str) -> list[dict]:
        """
        Run the trace (system and/or scapy), then enrich each hop with geo
        and reverse DNS.
        """
        loop = asyncio.get_running_loop()
        raw: list[dict] = []

        if self.method in ("auto", "system") and self._sys_available:
            try:
                raw = await loop.run_in_executor(None, self._trace_system, target)
                self._log(f"system traceroute → {target}: {len(raw)} raw hops")
            except Exception as e:
                self._log(f"system traceroute exception: {type(e).__name__}: {e}")
                raw = []

        if not raw and self.method in ("auto", "scapy"):
            try:
                raw = await loop.run_in_executor(None, self._trace_scapy, target)
                self._log(f"scapy traceroute → {target}: {len(raw)} raw hops")
            except Exception as e:
                self._log(f"scapy traceroute exception: {type(e).__name__}: {e}")
                raw = []

        enriched = []
        for h in raw:
            geo      = self.geo.lookup(h["ip"])
            hostname = None
            if self.dns is not None:
                hostname = self.dns.peek(h["ip"]) or self.dns.get(h["ip"])
            enriched.append({
                "ttl":      h["ttl"],
                "ip":       h["ip"],
                "rtt_ms":   h["rtt_ms"],
                "geo":      geo,
                "hostname": hostname,
            })
        return enriched

    # ─── Method 1: system binary ──────────────────────────────────────────
    def _trace_system(self, target: str) -> list[dict]:
        """
        Run the system traceroute/tracepath binary and parse its output.

        Flags used:
            -n      numeric output (no DNS)
            -m      max hops
            -w      per-hop timeout (seconds, rounded down to >= 1)
            -q 1    one probe per hop
        """
        cmd = [
            self.sys_cmd,
            "-n",
            "-m", str(self.max_hops),
            "-w", str(int(self.hop_timeout)) if self.hop_timeout >= 1 else "1",
            "-q", "1",
            target,
        ]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.max_hops * self.hop_timeout + 10,
                check=False,
            )
        except FileNotFoundError:
            self._log(f"{self.sys_cmd}: binary not found")
            return []
        except subprocess.TimeoutExpired:
            self._log(f"{self.sys_cmd}: overall timeout for {target}")
            return []

        out = proc.stdout or ""
        err = proc.stderr or ""
        if proc.returncode != 0 and not out:
            self._log(f"{self.sys_cmd} rc={proc.returncode} "
                      f"stderr={err.strip()[:200]}")

        hops = []
        for line in out.splitlines():
            m = _HOP_RE.match(line)
            if not m:
                continue
            hops.append({
                "ttl":    int(m.group(1)),
                "ip":     m.group(2),
                "rtt_ms": float(m.group(3)),
            })
        return hops

    # ─── Method 2: scapy fallback ─────────────────────────────────────────
    def _trace_scapy(self, target: str) -> list[dict]:
        """Run scapy's native traceroute and convert its output."""
        ans, _ = scapy_traceroute(
            target,
            maxttl=self.max_hops,
            verbose=0,
            timeout=self.hop_timeout,
        )
        out = []
        for snd, rcv in ans:
            rtt = None
            try:
                rtt = (rcv.time - snd.sent_time) * 1000.0
            except Exception:
                pass
            out.append({
                "ttl":    int(snd.ttl),
                "ip":     rcv.src,
                "rtt_ms": rtt,
            })
        return out
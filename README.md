# ip-geo-tracker – Live Network Flow Visualizer

[![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20A%20Coffee-shammmanek-FFDD00?style=flat-square&logo=buy-me-a-coffee&logoColor=black)](https://buymeacoffee.com/shammmanek)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> Sniff traffic on a network interface, geolocate every IP address, and
> watch connections appear in real time on an interactive world map.

`ip-geo-tracker` is a small, self-contained tool for visualizing network
traffic. It captures packets with **scapy**, groups them into flows,
resolves each source/destination IP to an approximate geographic location
using MaxMind and/or an online fallback, and streams the result to a
browser that renders flows as animated lines on a Leaflet map.

> **Note** — IP geolocation is approximate. It should not be used to
> determine a user's physical location. VPNs, proxies, CGNAT, mobile
> networks and incomplete databases can skew results significantly.

---

## Features

- **Live packet capture** on any Linux network interface (no root required
  when `CAP_NET_RAW` is granted to the Python interpreter).
- **Flow tracking** keyed by the 5-tuple `(src, sport, dst, dport, proto)`
  with idle-based expiration and TCP FIN/RST fast-close.
- **Geolocation** via the local MaxMind GeoLite2-City database, with an
  optional online fallback (`ip-api.com`).
- **Public-IP detection** so that LAN clients are anchored to the host's
  real geographic location.
- **Asynchronous reverse DNS** lookups for readable hostnames.
- **On-demand traceroute** with a persistent disk cache, using either the
  system `traceroute` binary or scapy as a fallback.
- **Persistent connection log** – every unique `(src, dst, proto)` triple
  is written to a timestamped log file.
- **Live filter** – search the connections list by IP, hostname or
  protocol.
- **Ignore list** – one click (or one "select all") hides a set of
  connections from the UI.
- **Single configuration file** – every tunable, including the basemap API
  key, lives in [`backend/config.py`](backend/config.py).

---

## Requirements

- **Linux** (for raw sockets and `CAP_NET_RAW`).
- **Python 3.10+**.
- A **MaxMind GeoLite2-City** database. Download the free database from
  <https://www.maxmind.com/en/geolite2/signup> and place the `.mmdb` file
  at `backend/GeoLite2-City.mmdb`.

Optional but recommended:

- The system `traceroute` binary (install via `apt install traceroute`
  or equivalent). If unavailable, `ip-geo-tracker` falls back to scapy.

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/<your-user>/ip-geo-tracker.git
cd ip-geo-tracker/backend

# 2. Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate

# 3. Install Python dependencies
pip install -r requirements.txt

# 4. (Optional) Download the MaxMind GeoLite2-City database and place it
#    in backend/GeoLite2-City.mmdb.

# 5. Grant raw-socket capabilities to the Python interpreter so that you
#    do not need to run the app as root.
sudo setcap cap_net_raw,cap_net_admin=eip "$(readlink -f "$(which python)")"
```

If you prefer not to modify your Python binary's capabilities, you can
instead run the backend with `sudo`. The first approach is recommended.

---

## Configuration

Every configurable value lives in a single file:

**`backend/config.py`**

Key settings:

| Setting | Purpose |
|---|---|
| `IFACE` | Network interface to sniff on (`ip link` lists them) |
| `HOST`, `PORT` | HTTP bind address and port |
| `IDLE_TIMEOUT` | Seconds of silence before a flow disappears |
| `GEO_DB_PATH` | Path to the MaxMind `.mmdb` file |
| `USE_EXTERNAL_IP` | Detect and use the public IP as LAN anchor |
| `DNS_ENABLED` | Toggle reverse DNS lookups |
| `TRACE_METHOD` | `"auto"`, `"system"` or `"scapy"` |
| `BASEMAP_API_KEY` | CartoDB (or other provider) tile API key (request key here https://carto.com/basemaps/apikey/ ) |
| `BASEMAP_URL_TEMPLATE` | Tile URL template; `{key}` is replaced at runtime |
| `MAP_DEFAULT_*` | Initial map centre and zoom |

The basemap key is delivered to the frontend at runtime through the
`/api/config` endpoint, so it is never hard-coded into JavaScript.

---

## Running

```bash
cd backend
python app.py
```

Then open <http://localhost:8000> in your browser.

You should see:

- A world map with a basemap layer.
- A **stats panel** in the top-left corner with live counters.
- A **connections list** in the bottom-left corner. Hover a row to
  highlight the corresponding line on the map; uncheck the box to add
  the connection to the ignore list; use the "All" checkbox to toggle
  every visible connection at once; type in the search box to filter by
  IP, hostname or protocol.
- Markers for every geolocated IP. Local addresses are jittered slightly
  around the host's location so they don't overlap.

---

## How it works

```
                ┌──────────────────────────────────────────────────┐
                │  capture thread (scapy)                          │
                │    • sniff(iface)                                │
                │    • flow_key_of(pkt)                            │
                │    • geo.lookup, dns.get, flow.update            │
                │    • emit into asyncio.Queue via call_soon_...   │
                └───────────────────────┬──────────────────────────┘
                                        │
                ┌───────────────────────▼──────────────────────────┐
                │  asyncio tasks (FastAPI event loop)              │
                │    • pump_events  →  broadcast to WebSockets     │
                │    • sweeper_task →  flow_down on idle           │
                │    • ticker_task  →  periodic flow snapshots     │
                │    • traceroute runner                           │
                └───────────────────────┬──────────────────────────┘
                                        │  WebSocket JSON events
                ┌───────────────────────▼──────────────────────────┐
                │  browser (frontend/app.js)                       │
                │    • Leaflet map + CartoDB tiles                 │
                │    • draws lines, arrows, markers, tooltips      │
                │    • connection list with filter + ignore        │
                └──────────────────────────────────────────────────┘
```

1. **scapy** runs `sniff()` in a dedicated thread and calls `_handle` for
   every packet.
2. Each packet is reduced to a flow key
   `(src, sport, dst, dport, proto)`.
3. `GeoResolver.lookup` and `DNSResolver.get` enrich the packet with
   location and reverse-DNS data.
4. `FlowTable.update` creates or refreshes the flow and returns a status
   (`new`, `revived`, or `None`).
5. New and revived flows trigger a `flow_up` event; closed flows trigger
   `flow_down`. Both are pushed into an `asyncio.Queue` in a thread-safe
   way.
6. The `pump_events` task drains the queue and broadcasts events to every
   connected WebSocket client.
7. The frontend renders each flow as a polyline + arrowhead and manages
   markers, tooltips, highlighting, filtering and the connection list.

---

## API

### HTTP

| Endpoint | Description |
|---|---|
| `GET /` | Serves the frontend |
| `GET /api/config` | Frontend runtime configuration (basemap, view) |
| `GET /api/me` | Detected public IP, fallback geo, ignore list |
| `GET /api/traceroute/{ip}` | Cached traceroute result, or queues a new one |
| `GET /api/test-traceroute/{ip}` | Debug: run both traceroute methods synchronously |

### WebSocket

`/ws`

Server → client messages:

| Type | Payload |
|---|---|
| `init` | Full flow snapshot + ignores + cached traces |
| `flow_up` | New or revived flow |
| `flow_down` | Flow was closed |
| `tick` | Periodic snapshot of active flows |
| `ignore_changed` | Acknowledgement of an ignore toggle |
| `local_ip_changed` | Public IP changed |
| `traceroute_pending` | A trace was queued |
| `traceroute_result` | Trace completed |

Client → server messages:

| Type | Payload |
|---|---|
| `set_ignore` | `{ conn_key: [src, dst], ignored: bool }` |
| `request_trace` | `{ target: "8.8.8.8" }` |

---

## Logs

Every connection is written once to a timestamped file in
`backend/logs/log_data_YYYY-MM-DD_HH-MM-SS.txt`:

```
timestamp | src_ip | src_host | src_place | dst_ip | dst_host | dst_place | proto
```

Deduplication is by `(src_ip, dst_ip, proto)`. The log file is created
fresh on every backend start.

---

## Limitations & caveats

- **Geolocation accuracy** is best at country level. City-level accuracy
  ranges from 50–75% and drops further for mobile/CGNAT networks.
- **VPNs and proxies** completely obscure the real endpoint location.
- **Private addresses** are always mapped to the host's public IP; you
  will never see the "real" location of a LAN client.
- **IPv6** is partially supported by scapy but not a primary target of
  this project.
- **Traceroute** requires outgoing UDP or ICMP; some networks block it.

---

## Project layout

```
ip-geo-tracker/
├── backend/
│   ├── app.py              # FastAPI application & lifespan
│   ├── capture.py          # scapy capture engine (background thread)
│   ├── config.py           # SINGLE configuration file
│   ├── connection_log.py   # persistent connection log
│   ├── dns.py              # async reverse-DNS resolver
│   ├── external_ip.py      # public-IP detection
│   ├── flows.py            # FlowTable
│   ├── geo.py              # IP geolocation resolver
│   ├── ignore.py           # ignore-list set
│   ├── traceroute.py       # traceroute service
│   ├── requirements.txt
│   └── logs/               # generated connection logs
└── frontend/
    ├── app.js              # WebSocket client + Leaflet rendering
    ├── index.html
    └── style.css
```

---

## Roadmap / ideas

- Persist closed flows to SQLite for session replay.
- Add filters by country, ASN or port.
- Animated line effects (`leaflet-ant-path`).
- Per-flow packet payload previews (for protocols you own).
- Optional login for LAN-only deployment.

---

## Support the project

`ip-geo-tracker` is developed and maintained in my free time, with no
corporate backing and no ads. If you'd like to say thanks, you can buy me
a coffee:

[![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20A%20Coffee-shammmanek-FFDD00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black)](https://buymeacoffee.com/shammmanek)

Every coffee is appreciated — it directly funds new features, better
geolocation, and more map overlays. Thank you! ❤️

---

## License

This project is licensed under the **MIT License**. See the `LICENSE` file
for details.
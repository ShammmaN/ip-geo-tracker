"""
netviz – central configuration file.

This is the SINGLE source of truth for every tunable parameter used by the
backend (FastAPI server, packet capture, traceroute, geolocation) and by the
frontend (map tiles, default view, attribution).

Do NOT scatter configuration constants across other modules — import them
from here instead.
"""

# ─── Network interface & HTTP server ──────────────────────────────────────
IFACE = "wlan0"          # Network interface to sniff on (list with `ip link`)
HOST  = "0.0.0.0"        # HTTP bind address
PORT  = 8000             # HTTP bind port

# ─── Flow tracking ────────────────────────────────────────────────────────
IDLE_TIMEOUT      = 10.0   # Seconds of silence before a flow is removed
REVIVE_THRESHOLD  = 2.0    # Idle time after which a flow counts as "revived"
SWEEP_INTERVAL    = 2.0    # How often the backend sweeps expired flows (s)
TICK_INTERVAL     = 0.5    # How often the frontend receives flow snapshots (s)

# ─── Geolocation ──────────────────────────────────────────────────────────
GEO_DB_PATH = "GeoLite2-City.mmdb"   # Path to the MaxMind GeoLite2-City database

# ─── External IP resolver ─────────────────────────────────────────────────
EXTERNAL_IP_REFRESH = 600    # Refresh interval for public-IP detection (s)
USE_EXTERNAL_IP     = True   # Detect public IP and use it as a LAN marker

# ─── Reverse DNS ──────────────────────────────────────────────────────────
DNS_ENABLED = True   # Enable asynchronous reverse DNS lookups
DNS_WORKERS = 8      # Thread pool size for DNS resolution

# ─── Traceroute ───────────────────────────────────────────────────────────
TRACE_CACHE_FILE = "trace_cache.json"   # Persistent trace cache file
TRACE_CACHE_TTL  = None                 # Cache TTL in seconds (None = forever)

# "auto"   = try the system command first, fall back to scapy
# "system" = use only the system traceroute/tracepath binary
# "scapy"  = use only scapy's traceroute implementation
TRACE_METHOD = "auto"

TRACE_SYS_CMD        = "traceroute"   # or "tracepath" if traceroute is missing
TRACE_MAX_HOPS       = 20             # Maximum TTL value to probe
TRACE_HOP_TIMEOUT    = 1.5            # Per-hop timeout in seconds
TRACE_MAX_CONCURRENT = 2              # Number of concurrent traceroute jobs
TRACE_MIN_INTERVAL   = 2.0            # Minimum delay between trace starts (s)
TRACE_DEBUG          = True           # Verbose traceroute logging

# ─── Fallback geolocation for private IPs ─────────────────────────────────
# Used when neither the external-IP resolver nor a manual override is
# available (e.g. fully offline environments).
LOCAL_GEO = {
    "ip": "local",
    "lat": 52.2297,
    "lon": 21.0122,
    "country": "Poland",
    "city": "Warsaw",
    "asn": None,
    "org": "LAN",
    "is_local": True,
}

# ─── Frontend / Map ───────────────────────────────────────────────────────
# Basemap tile provider. The API key is exposed to the frontend through the
# /api/config endpoint — the frontend never hard-codes it.
BASEMAP_URL_TEMPLATE = (
    "https://basemaps.cartocdn.com/rastertiles/voyager/"
    "{z}/{x}/{y}.png?key={key}"
)
BASEMAP_API_KEY     = ""
BASEMAP_ATTRIBUTION = "© OpenStreetMap, © CARTO"
BASEMAP_SUBDOMAINS  = "abcd"
BASEMAP_MAX_ZOOM    = 18

MAP_DEFAULT_LAT  = 20    # Initial map center latitude
MAP_DEFAULT_LON  = 0     # Initial map center longitude
MAP_DEFAULT_ZOOM = 2     # Initial zoom level

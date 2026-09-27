"""
netviz – public IP detection.

Queries a list of HTTP providers to discover the machine's public IPv4
address together with its approximate geolocation. The result is used as
the "source" marker for every private LAN address.
"""

import json
import threading
import time
import urllib.request


class ExternalIPResolver:
    """
    Detect and cache the host's public IP + geolocation.

    Parameters
    ----------
    refresh_interval : seconds between automatic refreshes
    """

    # Providers are tried in order; the first successful response wins.
    PROVIDERS = [
        # ip-api.com – free, returns IP + geo in a single request
        "http://ip-api.com/json/?fields=status,query,country,city,lat,lon,as,org",
        # fallback: ipwho.is
        "https://ipwho.is/",
    ]

    def __init__(self, refresh_interval: int = 600):
        self.refresh_interval = refresh_interval
        self.data: dict | None = None
        self.last_fetch: float = 0.0
        self._lock = threading.Lock()

    # ─── Helpers ──────────────────────────────────────────────────────────
    def _fetch(self, url: str) -> dict:
        """Fetch and JSON-decode a single provider URL."""
        with urllib.request.urlopen(url, timeout=5) as r:
            return json.loads(r.read().decode())

    def _normalize(self, raw: dict) -> dict | None:
        """Convert provider-specific payloads into the canonical schema."""
        # ip-api.com
        if "query" in raw:
            if raw.get("status") != "success":
                return None
            ip       = raw.get("query")
            lat, lon = raw.get("lat"), raw.get("lon")
        # ipwho.is
        elif "ip" in raw:
            if not raw.get("success", True):
                return None
            ip       = raw.get("ip")
            lat, lon = raw.get("latitude"), raw.get("longitude")
        else:
            return None

        if not ip or lat is None or lon is None:
            return None

        return {
            "ip":          ip,
            "external_ip": ip,
            "lat":         lat,
            "lon":         lon,
            "country":     raw.get("country", "") or "",
            "city":        raw.get("city", "") or "",
            "asn":         None,
            "org":         raw.get("org", "") or raw.get("connection", {}).get("org", ""),
            "is_local":    True,
        }

    # ─── Public API ───────────────────────────────────────────────────────
    def refresh(self, force: bool = False) -> dict | None:
        """
        Refresh the cached public IP if it is stale or `force` is True.

        Returns the current data dict (which may be the previous value if
        every provider failed).
        """
        with self._lock:
            now = time.time()
            if (not force and self.data
                    and (now - self.last_fetch) < self.refresh_interval):
                return self.data

            for url in self.PROVIDERS:
                try:
                    raw  = self._fetch(url)
                    data = self._normalize(raw)
                    if data:
                        self.data       = data
                        self.last_fetch = now
                        print(f"[external-ip] public IP = {data['ip']} "
                              f"({data['city']}, {data['country']})")
                        return data
                except Exception as e:
                    print(f"[external-ip] {url} failed: {e}")
                    continue
            return self.data

    def get(self) -> dict | None:
        """Return the currently cached public IP data (or None)."""
        return self.data
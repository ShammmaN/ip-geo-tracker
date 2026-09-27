"""
netviz – IP geolocation resolver.

Resolution order for a given IP:
    1. If the IP equals the detected external/public IP → return its geo.
    2. If it is a private / loopback / multicast IP → return the geo of
       the public IP (or the manual LOCAL_GEO fallback).
    3. Otherwise, try the local MaxMind GeoLite2-City database.
    4. If the database is unavailable and `online_fallback` is enabled,
       query the ip-api.com HTTP endpoint.

All results are cached in-memory for the process lifetime.
"""

import ipaddress
import json
import threading
import time
import urllib.request

import geoip2.database


# Networks that are never publicly routable.
PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


class GeoResolver:
    """
    Resolve IP addresses to approximate geographic coordinates.

    Parameters
    ----------
    db_path          : path to GeoLite2-City.mmdb (may not exist)
    local_geo        : manual fallback for private IPs (dict)
    external_resolver: ExternalIPResolver instance (or None)
    online_fallback  : query ip-api.com if the MaxMind DB is unavailable
    """

    def __init__(self, db_path: str, local_geo: dict | None = None,
                 external_resolver=None, online_fallback: bool = True):
        self.local_geo       = local_geo
        self.external        = external_resolver
        self.online_fallback = online_fallback
        self._cache: dict[str, dict | None] = {}
        self._lock           = threading.Lock()
        self.reader          = None
        try:
            self.reader = geoip2.database.Reader(db_path)
            print(f"[geo] loaded MaxMind DB: {db_path}")
        except Exception as e:
            print(f"[geo] MaxMind DB not available ({e})")
            if online_fallback:
                print("[geo] using ip-api.com online fallback")

    # ─── Helpers ──────────────────────────────────────────────────────────
    @staticmethod
    def is_private(ip: str) -> bool:
        """True if `ip` is RFC1918 / loopback / link-local / multicast."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return True
        return any(addr in net for net in PRIVATE_NETS)

    def _lookup_online(self, ip: str) -> dict | None:
        """Query ip-api.com for a public IP (no API key required, rate-limited)."""
        try:
            url = (
                f"http://ip-api.com/json/{ip}"
                f"?fields=status,country,city,lat,lon,as,org"
            )
            with urllib.request.urlopen(url, timeout=3) as resp:
                data = json.loads(resp.read().decode())
            if data.get("status") != "success":
                return None
            return {
                "ip":       ip,
                "lat":      data["lat"],
                "lon":      data["lon"],
                "country":  data.get("country", ""),
                "city":     data.get("city", ""),
                "asn":      None,
                "org":      data.get("org", ""),
                "is_local": False,
            }
        except Exception:
            return None

    def _local_geo_for(self, private_ip: str) -> dict | None:
        """
        Map a private IP to the geolocation of the public IP.

        The original private IP is preserved in the `ip` field so that the
        frontend can still distinguish LAN clients, while `external_ip`
        records the routed public address.
        """
        # 1) Prefer freshly detected external IP.
        if self.external is not None:
            ext = self.external.get()
            if ext:
                result = dict(ext)              # copy, do not mutate original
                result["external_ip"] = ext["ip"]
                result["ip"]          = private_ip
                result["is_local"]    = True
                return result

        # 2) Manual fallback.
        if self.local_geo is not None:
            result = dict(self.local_geo)
            result["ip"]       = private_ip
            result["is_local"] = True
            return result

        return None

    # ─── Public API ───────────────────────────────────────────────────────
    def lookup(self, ip: str) -> dict | None:
        """
        Resolve `ip` to a dict with keys:
            ip, lat, lon, country, city, asn, org, is_local[, external_ip]

        Returns None if the IP cannot be resolved.
        """
        # The public IP of this host is treated as "local".
        if self.external is not None:
            ext = self.external.get()
            if ext and ip == ext["ip"]:
                return {**ext, "ip": ip, "is_local": True}

        with self._lock:
            if ip in self._cache:
                return self._cache[ip]

        if self.is_private(ip):
            result = self._local_geo_for(ip)
        elif self.reader is not None:
            try:
                r = self.reader.city(ip)
                if (r.location.latitude is not None
                        and r.location.longitude is not None):
                    result = {
                        "ip":       ip,
                        "lat":      r.location.latitude,
                        "lon":      r.location.longitude,
                        "country":  r.country.name or "",
                        "city":     r.city.name or "",
                        "asn":      r.traits.autonomous_system_number,
                        "org":      r.traits.autonomous_system_organization or "",
                        "is_local": False,
                    }
                else:
                    result = None
            except Exception:
                result = None
        elif self.online_fallback:
            result = self._lookup_online(ip)
            time.sleep(0.05)   # respect ip-api.com rate limit (45 req/min)
        else:
            result = None

        with self._lock:
            self._cache[ip] = result
        return result
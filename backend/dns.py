"""
netviz – asynchronous reverse-DNS resolver.

`get()` never blocks: it returns a cached hostname or None (and schedules a
background lookup). `peek()` returns whatever is already cached.
"""

import socket
import threading
from concurrent.futures import ThreadPoolExecutor


class DNSResolver:
    """
    Non-blocking reverse-DNS with an internal cache and thread pool.

    Parameters
    ----------
    workers     : number of worker threads performing PTR lookups
    max_pending : maximum number of in-flight lookups (backpressure)
    """

    def __init__(self, workers: int = 8, max_pending: int | None = None):
        self._cache: dict[str, str | None] = {}
        self._pending: set[str] = set()
        self._lock = threading.Lock()
        self._pool = ThreadPoolExecutor(
            max_workers=workers,
            thread_name_prefix="dns",
        )
        self._max_pending = max_pending or workers * 4

    # ─── Public API ───────────────────────────────────────────────────────
    def get(self, ip: str) -> str | None:
        """
        Return the hostname for `ip` if cached, otherwise schedule a lookup
        and return None. Never blocks.
        """
        with self._lock:
            if ip in self._cache:
                return self._cache[ip]
            if ip in self._pending:
                return None
            if len(self._pending) >= self._max_pending:
                return None                          # backpressure
            self._pending.add(ip)

        self._pool.submit(self._resolve, ip)
        return None

    def peek(self, ip: str) -> str | None:
        """Return the cached hostname without triggering a new lookup."""
        with self._lock:
            return self._cache.get(ip)

    # ─── Internal ─────────────────────────────────────────────────────────
    def _resolve(self, ip: str) -> None:
        """Perform the blocking PTR lookup and store the result."""
        hostname: str | None = None
        try:
            result   = socket.gethostbyaddr(ip)
            hostname = result[0].rstrip(".")
            # Filter out garbage: empty strings or the IP echoed back.
            if not hostname or hostname == ip:
                hostname = None
        except Exception:
            hostname = None

        with self._lock:
            self._cache[ip] = hostname
            self._pending.discard(ip)
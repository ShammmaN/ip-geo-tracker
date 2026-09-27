"""
netviz – ignore list.

Stores (src_ip, dst_ip) pairs whose packets must be dropped by the capture
engine. Thread-safe.
"""

from threading import Lock


class IgnoreSet:
    """Set of ignored connection pairs (src_ip, dst_ip)."""

    def __init__(self):
        self._set: set[tuple] = set()
        self._lock = Lock()

    def is_ignored(self, src_ip: str, dst_ip: str) -> bool:
        """True if the (src, dst) pair is on the ignore list."""
        with self._lock:
            return (src_ip, dst_ip) in self._set

    def add(self, src_ip: str, dst_ip: str) -> bool:
        """Add a pair. Returns True if it was newly added."""
        with self._lock:
            if (src_ip, dst_ip) in self._set:
                return False
            self._set.add((src_ip, dst_ip))
            return True

    def remove(self, src_ip: str, dst_ip: str) -> bool:
        """Remove a pair. Returns True if it was present."""
        with self._lock:
            if (src_ip, dst_ip) not in self._set:
                return False
            self._set.discard((src_ip, dst_ip))
            return True

    def all(self) -> list[tuple]:
        """Return a snapshot of all ignored pairs."""
        with self._lock:
            return list(self._set)
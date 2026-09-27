"""
netviz – flow tracking.

A `Flow` represents a single unidirectional 5-tuple. `FlowTable` stores all
active flows behind a lock and provides update / close / sweep / snapshot
operations. Timeouts are idle-based, not strict-TTL.
"""

import time
from dataclasses import dataclass
from threading import Lock


@dataclass
class Flow:
    """State for one bidirectional-unaware connection (per 5-tuple)."""
    key:        tuple
    src_geo:    dict
    dst_geo:    dict
    proto:      int
    first_seen: float
    last_seen:  float
    packets:    int = 0
    bytes:      int = 0
    state:      str = "new"

    def to_dict(self) -> dict:
        """Serialize the flow for the WebSocket layer."""
        return {
            "key":        list(self.key),
            "src":        self.src_geo,
            "dst":        self.dst_geo,
            "proto":      self.proto,
            "packets":    self.packets,
            "bytes":      self.bytes,
            "first_seen": self.first_seen,
            "last_seen":  self.last_seen,
            "state":      self.state,
        }


class FlowTable:
    """
    Thread-safe collection of active flows.

    Parameters
    ----------
    idle_timeout      : seconds of inactivity before a flow is expired by `sweep()`
    revive_threshold  : seconds of inactivity after which a new packet on an
                        existing flow is reported as `revived`
    """

    def __init__(self, idle_timeout: float = 10.0, revive_threshold: float = 2.0):
        self.flows: dict[tuple, Flow] = {}
        self.idle_timeout      = idle_timeout
        self.revive_threshold  = revive_threshold
        self.lock = Lock()

    # ─── Update / create ──────────────────────────────────────────────────
    def update(self, key, src_geo, dst_geo, proto, length):
        """
        Update an existing flow or create a new one.

        Returns
        -------
        (flow, status) where status is one of:
            None      – existing flow, just updated counters
            "new"     – flow was newly created
            "revived" – existing flow, previously idle for > revive_threshold
        """
        now = time.time()
        with self.lock:
            flow = self.flows.get(key)
            if flow is None:
                flow = Flow(
                    key=key, src_geo=src_geo, dst_geo=dst_geo, proto=proto,
                    first_seen=now, last_seen=now, packets=1, bytes=length,
                    state="new",
                )
                self.flows[key] = flow
                return flow, "new"

            was_idle_for = now - flow.last_seen
            flow.last_seen = now
            flow.packets  += 1
            flow.bytes    += length
            flow.state     = "active"

            if was_idle_for > self.revive_threshold:
                return flow, "revived"
            return flow, None

    # ─── Removal ──────────────────────────────────────────────────────────
    def close(self, key):
        """Remove and return a flow by key, or None if it doesn't exist."""
        with self.lock:
            return self.flows.pop(key, None)

    def close_by_connection(self, src_ip: str, dst_ip: str) -> list[tuple]:
        """Remove all flows matching the (src_ip, dst_ip) pair; return keys."""
        with self.lock:
            keys = [k for k in self.flows if k[0] == src_ip and k[2] == dst_ip]
            for k in keys:
                del self.flows[k]
            return keys

    def sweep(self) -> list[tuple]:
        """Remove and return keys of all flows idle for > idle_timeout."""
        now = time.time()
        with self.lock:
            expired = [
                k for k, f in self.flows.items()
                if now - f.last_seen > self.idle_timeout
            ]
            for k in expired:
                del self.flows[k]
        return expired

    # ─── Snapshot ─────────────────────────────────────────────────────────
    def snapshot(self, active_window: float | None = None) -> list[dict]:
        """
        Return a serialized list of flows.

        If `active_window` is given, only flows whose last packet arrived
        within that window (in seconds) are included.
        """
        now = time.time()
        with self.lock:
            result = []
            for f in self.flows.values():
                if active_window is not None and (now - f.last_seen) > active_window:
                    continue
                d = f.to_dict()
                d["bps"]  = f.bytes / max(now - f.first_seen, 0.001)
                d["idle"] = now - f.last_seen
                result.append(d)
            return result
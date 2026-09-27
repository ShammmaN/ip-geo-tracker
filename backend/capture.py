"""
netviz – packet capture engine.

Runs scapy's synchronous `sniff()` on a background thread and forwards
parsed events into an asyncio.Queue via `loop.call_soon_threadsafe`. The
main asyncio loop consumes the queue and broadcasts events to all clients.
"""

import asyncio
from scapy.all import sniff, IP, TCP, UDP, ICMP


def flow_key_of(pkt) -> tuple:
    """
    Build a 5-tuple flow key from a scapy packet.

    The key uniquely identifies a unidirectional flow:
        (src_ip, src_port, dst_ip, dst_port, ip_protocol)

    Ports are set to None for protocols that do not have them (ICMP).
    For unknown protocols only (src, dst, proto) is used.
    """
    ip = pkt[IP]
    if TCP in pkt:
        t = pkt[TCP]
        return (ip.src, int(t.sport), ip.dst, int(t.dport), 6)
    if UDP in pkt:
        u = pkt[UDP]
        return (ip.src, int(u.sport), ip.dst, int(u.dport), 17)
    if ICMP in pkt:
        return (ip.src, None, ip.dst, None, 1)
    return (ip.src, None, ip.dst, None, int(ip.proto))


class CaptureEngine:
    """
    Sniff packets on `iface`, update flow / geo / log state and emit events.

    Emitted events (all dicts with a `type` field):
        * `flow_up`   – a new or revived flow has been observed
        * `flow_down` – a flow was closed (FIN/RST, ignore, or timeout)
    """

    def __init__(self, iface, geo, flows, dns, ignore, conn_log,
                 loop: asyncio.AbstractEventLoop):
        """
        Parameters
        ----------
        iface      : network interface to sniff on
        geo        : GeoResolver instance
        flows      : FlowTable instance
        dns        : DNSResolver instance (or None)
        ignore     : IgnoreSet instance
        conn_log   : ConnectionLogger instance (or None)
        loop       : asyncio event loop used for thread-safe queue hand-off
        """
        self.iface    = iface
        self.geo      = geo
        self.flows    = flows
        self.dns      = dns
        self.ignore   = ignore
        self.conn_log = conn_log
        self.loop     = loop
        self.queue: asyncio.Queue = asyncio.Queue()

    # ─── Internal helpers ─────────────────────────────────────────────────
    def _emit(self, event: dict) -> None:
        """Thread-safe push of an event into the asyncio queue."""
        self.loop.call_soon_threadsafe(self.queue.put_nowait, event)

    def _handle(self, pkt) -> None:
        """
        Called by scapy for every captured packet.

        Steps:
            1. Drop packets whose (src, dst) pair is on the ignore list
               (closing any existing flow first).
            2. Resolve geolocation for src and dst; drop if either fails.
            3. Update the flow table; emit `flow_up` on new/revived flows.
            4. Log the connection (once per unique triple).
            5. Close the flow immediately on TCP FIN or RST.
        """
        if IP not in pkt:
            return
        ip = pkt[IP]

        # 1) Ignored connection? Close any existing flow and drop the packet.
        if self.ignore.is_ignored(ip.src, ip.dst):
            key     = flow_key_of(pkt)
            closed  = self.flows.close(key)
            if closed is not None:
                self._emit({"type": "flow_down", "key": list(key)})
            return

        # 2) Geolocation
        src_geo = self.geo.lookup(ip.src)
        dst_geo = self.geo.lookup(ip.dst)
        if not (src_geo and dst_geo):
            return

        src_geo = {**src_geo, "hostname": self.dns.get(ip.src) if self.dns else None}
        dst_geo = {**dst_geo, "hostname": self.dns.get(ip.dst) if self.dns else None}

        # 3) Flow tracking
        key  = flow_key_of(pkt)
        flow, status = self.flows.update(
            key, src_geo, dst_geo, int(ip.proto), len(pkt),
        )

        if status in ("new", "revived"):
            # 4) Log once per unique (src, dst, proto) triple.
            if status == "new" and self.conn_log is not None:
                self.conn_log.log(src_geo, dst_geo, int(ip.proto))

            self._emit({
                "type":   "flow_up",
                "flow":   flow.to_dict(),
                "status": status,
            })

        # 5) Immediate close on TCP FIN (0x01) or RST (0x04).
        if TCP in pkt:
            flags = int(pkt[TCP].flags)
            if flags & 0x01 or flags & 0x04:
                closed = self.flows.close(key)
                if closed is not None:
                    self._emit({"type": "flow_down", "key": list(key)})

    # ─── Entry point ──────────────────────────────────────────────────────
    def start(self) -> None:
        """Blocking sniff loop – call from a dedicated thread."""
        try:
            print(f"[capture] sniffing on {self.iface}")
            sniff(iface=self.iface, prn=self._handle, store=False)
        except Exception as e:
            print(f"[capture] error: {e}")
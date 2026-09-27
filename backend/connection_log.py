"""
netviz – persistent connection log.

Writes one line per unique (src_ip, dst_ip, proto) triple to a timestamped
file inside the log directory. Deduplication is handled in-memory.
"""

import os
from datetime import datetime
from threading import Lock


class ConnectionLogger:
    """
    Log detected connections to `log_data_YYYY-MM-DD_HH-MM-SS.txt`.

    Parameters
    ----------
    log_dir : directory where log files are created (created if missing)
    """

    def __init__(self, log_dir: str):
        os.makedirs(log_dir, exist_ok=True)
        ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        self.path = os.path.join(log_dir, f"log_data_{ts}.txt")
        self._seen: set[tuple] = set()
        self._lock = Lock()

        # Write the header once.
        with open(self.path, "w", encoding="utf-8") as f:
            f.write("# netviz connection log\n")
            f.write(f"# started: {datetime.now().isoformat(timespec='seconds')}\n")
            f.write("# format:  timestamp | src_ip | src_host | src_place | "
                    "dst_ip | dst_host | dst_place | proto\n")
            f.write("#" + "-" * 100 + "\n")

        print(f"[log] connection log: {self.path}")

    # ─── Public API ───────────────────────────────────────────────────────
    def log(self, src: dict, dst: dict, proto: int) -> bool:
        """
        Write a single connection line.

        Returns True if the line was written, False if it was already logged
        (or writing failed).
        """
        key = (src["ip"], dst["ip"], proto)
        with self._lock:
            if key in self._seen:
                return False
            self._seen.add(key)

            ts        = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            src_place = ", ".join(filter(None, [src.get("city"), src.get("country")]))
            dst_place = ", ".join(filter(None, [dst.get("city"), dst.get("country")]))
            src_host  = src.get("hostname") or "-"
            dst_host  = dst.get("hostname") or "-"

            line = (
                f"{ts} | "
                f"{src['ip']} | {src_host} | {src_place or '-'} | "
                f"{dst['ip']} | {dst_host} | {dst_place or '-'} | "
                f"{proto}\n"
            )
            try:
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(line)
            except Exception as e:
                print(f"[log] write error: {e}")
                return False
            return True

    @property
    def seen_count(self) -> int:
        """Number of unique connections logged so far."""
        with self._lock:
            return len(self._seen)
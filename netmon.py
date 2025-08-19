import argparse
import csv
import signal
import sys
import time
from collections import defaultdict, deque
from datetime import datetime

from scapy.all import sniff, IP, IPv6, TCP, UDP, DNS, Raw

# -------------------- Config & State --------------------

class RollingWindow:
    """Keep timestamps in a sliding time window."""
    def __init__(self, window_seconds: int):
        self.window = deque()
        self.window_seconds = window_seconds

    def add(self, ts: float, value=None):
        self.window.append((ts, value))
        self.prune(ts)

    def prune(self, now: float):
        cutoff = now - self.window_seconds
        while self.window and self.window[0][0] < cutoff:
            self.window.popleft()

    def values(self):
        return [v for _, v in self.window]

    def _len_(self):
        return len(self.window)


def human_ts(ts: float = None) -> str:
    return datetime.fromtimestamp(ts if ts is not None else time.time()).strftime("%Y-%m-%d %H:%M:%S")


class NetMon:
    def __init__(
        self,
        iface: str,
        log_file: str,
        scan_window: int,
        scan_port_threshold: int,
        ssh_window: int,
        ssh_attempt_threshold: int,
        bpf_filter: str = None
    ):
        self.iface = iface
        self.log_file = log_file
        self.scan_window = scan_window
        self.scan_port_threshold = scan_port_threshold
        self.ssh_window = ssh_window
        self.ssh_attempt_threshold = ssh_attempt_threshold
        self.bpf_filter = bpf_filter

        # Stats
        self.total_packets = 0
        self.total_bytes = 0
        self.proto_counts = defaultdict(int)      # e.g., "TCP", "UDP", "DNS"
        self.src_counts = defaultdict(int)        # packets per source IP
        self.dst_port_counts = defaultdict(int)   # packets per destination port

        # Detection structures
        self.port_scan_tracker = defaultdict(lambda: defaultdict(lambda: RollingWindow(self.scan_window)))
        # structure: src_ip -> dport -> RollingWindow(ts only)
        self.port_scan_unique_port_window = defaultdict(lambda: RollingWindow(self.scan_window))
        # track distinct dports seen per src in window

        self.ssh_attempts = defaultdict(lambda: RollingWindow(self.ssh_window))  # src_ip -> timestamps

        # CSV logger
        self.csv_fp = open(self.log_file, "a", newline="", encoding="utf-8")
        self.csv_writer = csv.writer(self.csv_fp)
        # Write header if file empty
        try:
            if self.csv_fp.tell() == 0:
                self.csv_writer.writerow(["time", "src", "dst", "proto", "sport", "dport", "size_bytes", "info"])
                self.csv_fp.flush()
        except Exception:
            pass

        # graceful stop
        self._stop = False
        signal.signal(signal.SIGINT, self._handle_stop)
        signal.signal(signal.SIGTERM, self._handle_stop)

        self._last_stat_print = 0

    def _handle_stop(self, *args):
        self._stop = True

    def _log(self, src, dst, proto, sport, dport, size, info):
        self.csv_writer.writerow([human_ts(), src, dst, proto, sport, dport, size, info])
        # flush lightly—avoid too frequent flush for performance, but keep it simple:
        self.csv_fp.flush()

    # -------------------- Detection Heuristics --------------------

    def _check_port_scan(self, src_ip: str, dport: int, now: float):
        """
        Heuristic: if a source hits many distinct destination ports
        within scan_window seconds, raise possible port scan alert.
        """
        # Track this dport occurrence
        port_window = self.port_scan_tracker[src_ip][dport]
        port_window.add(now)
        # Mark unique port seen in global window for this src
        # We'll store the dport in the values to compute uniqueness
        self.port_scan_unique_port_window[src_ip].add(now, dport)

        # Count distinct ports in current window
        distinct_ports = len(set(self.port_scan_unique_port_window[src_ip].values()))
        if distinct_ports >= self.scan_port_threshold:
            print(f"[ALERT] {human_ts(now)} Possible PORT SCAN by {src_ip}: "
                  f"{distinct_ports} distinct destination ports in ~{self.scan_window}s")
            # Reset to avoid spamming repeated alerts
            self.port_scan_unique_port_window[src_ip] = RollingWindow(self.scan_window)

    def _check_ssh_bruteforce(self, src_ip: str, dport: int, now: float):
        """
        Heuristic: many connection attempts to SSH (port 22) from same IP in short time.
        """
        if dport == 22:
            self.ssh_attempts[src_ip].add(now)
            if len(self.ssh_attempts[src_ip]) >= self.ssh_attempt_threshold:
                print(f"[ALERT] {human_ts(now)} Possible SSH BRUTE-FORCE from {src_ip}: "
                      f"{len(self.ssh_attempts[src_ip])} attempts in ~{self.ssh_window}s")
                # Reset window to throttle alerts
                self.ssh_attempts[src_ip] = RollingWindow(self.ssh_window)

    # -------------------- Packet Handling --------------------

    def handle_packet(self, pkt):
        now = time.time()
        self.total_packets += 1

        src = dst = "-"
        sport = dport = "-"
        size = len(pkt.original) if hasattr(pkt, "original") else len(bytes(pkt))
        self.total_bytes += size
        proto = "OTHER"
        info = ""

        # IPv4 / IPv6 basics
        ip_layer = None
        if IP in pkt:
            ip_layer = pkt[IP]
            src, dst = ip_layer.src, ip_layer.dst
        elif IPv6 in pkt:
            ip_layer = pkt[IPv6]
            src, dst = ip_layer.src, ip_layer.dst

        if TCP in pkt:
            proto = "TCP"
            sport, dport = pkt[TCP].sport, pkt[TCP].dport
            flags = pkt[TCP].flags
            info = f"TCP flags={flags}"
            self.dst_port_counts[dport] += 1

            # Detections
            if ip_layer is not None:
                self._check_port_scan(src, dport, now)
                self._check_ssh_bruteforce(src, dport, now)

        elif UDP in pkt:
            proto = "UDP"
            sport, dport = pkt[UDP].sport, pkt[UDP].dport
            self.dst_port_counts[dport] += 1

        if DNS in pkt:
            proto = "DNS" if pkt[DNS].qd is not None else proto
            try:
                qname = pkt[DNS].qd.qname.decode(errors="ignore") if pkt[DNS].qd else ""
            except Exception:
                qname = ""
            info = f"DNS query={qname}" if qname else info

        if ip_layer is not None:
            self.src_counts[src] += 1
        self.proto_counts[proto] += 1

        # log row
        self._log(src, dst, proto, sport, dport, size, info)

        # periodic concise stats to console
        if now - self._last_stat_print >= 5:  # every ~5s
            self._last_stat_print = now
            self.print_brief_stats()

    def print_brief_stats(self):
        mb = self.total_bytes / (1024 * 1024)
        top_proto = sorted(self.proto_counts.items(), key=lambda x: x[1], reverse=True)[:4]
        top_ports = sorted(self.dst_port_counts.items(), key=lambda x: x[1], reverse=True)[:5]

        print("\n---------------- Live Stats ----------------")
        print(f"Time: {human_ts()}  |  Packets: {self.total_packets:,}  |  Data: {mb:.2f} MB")
        if top_proto:
            print("Top Protocols:", ", ".join([f"{p}:{c}" for p, c in top_proto]))
        if top_ports:
            print("Top Dst Ports:", ", ".join([f"{p}:{c}" for p, c in top_ports]))
        print("-------------------------------------------\n")

    def close(self):
        try:
            self.csv_fp.flush()
            self.csv_fp.close()
        except Exception:
            pass

    # -------------------- Run --------------------

    def run(self):
        print(f"[INFO] Interface: {self.iface} | Log: {self.log_file}")
        if self.bpf_filter:
            print(f"[INFO] BPF filter: {self.bpf_filter}")
        print(f"[INFO] Scan window: {self.scan_window}s, threshold: {self.scan_port_threshold} ports")
        print(f"[INFO] SSH window: {self.ssh_window}s, threshold: {self.ssh_attempt_threshold} attempts")
        print("[INFO] Press Ctrl+C to stop.\n")

        try:
            sniff(
                iface=self.iface if self.iface else None,
                prn=self.handle_packet,
                store=False,
                filter=self.bpf_filter  # may be None
            )
        except Exception as e:
            print(f"[ERROR] Sniff failed: {e}")
        finally:
            self.close()
            self.summary()

    def summary(self):
        print("\n=========== Session Summary ===========")
        print(f"Stopped: {human_ts()}")
        print(f"Total packets: {self.total_packets:,}")
        print(f"Total bytes: {self.total_bytes:,}")
        print("Protocols:")
        for p, c in sorted(self.proto_counts.items(), key=lambda x: x[1], reverse=True):
            print(f"  {p}: {c}")
        print("Top 10 source IPs:")
        for ip, c in sorted(self.src_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
            print(f"  {ip}: {c}")
        print("Top 10 destination ports:")
        for port, c in sorted(self.dst_port_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
            print(f"  {port}: {c}")
        print(f"Log file: {self.log_file}")
        print("=======================================\n")


def parse_args():
    ap = argparse.ArgumentParser(description="Simple Network Monitoring Tool (Scapy)")
    ap.add_argument("-i", "--iface", help="Interface to sniff (e.g., eth0, wlan0). Omit for default.")
    ap.add_argument("--log", default="netmon_log.csv", help="CSV log file path.")
    ap.add_argument("--scan-window", type=int, default=10, help="Port-scan time window seconds.")
    ap.add_argument("--scan-ports", type=int, default=20, help="Distinct ports threshold within window.")
    ap.add_argument("--ssh-window", type=int, default=20, help="SSH brute-force window seconds.")
    ap.add_argument("--ssh-attempts", type=int, default=15, help="SSH attempts threshold within window.")
    ap.add_argument("--bpf", help='Optional BPF filter (tcp, udp, "port 80", "host 1.2.3.4" etc.)')
    return ap.parse_args()


def main():
    args = parse_args()
    monitor = NetMon(
        iface=args.iface,
        log_file=args.log,
        scan_window=args.scan_window,
        scan_port_threshold=args.scan_ports,
        ssh_window=args.ssh_window,
        ssh_attempt_threshold=args.ssh_attempts,
        bpf_filter=args.bpf
    )
    monitor.run()


if __name__ == "__main__":
    main()
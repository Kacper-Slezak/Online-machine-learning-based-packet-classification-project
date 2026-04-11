from scapy.all import sniff, PcapWriter, conf, get_if_list
from scapy.layers.inet import IP, TCP, UDP
import psutil
import threading
import time
import os
import socket
from datetime import datetime
from collections import defaultdict

# ─── Configuration ─────────────────────────────────────────────────────────────

TARGET_APPS    = ["spotify"]
DIR_FOR_SAVING = "traffic_logs"
DEBUG          = True

# ──────────────────────────────────────────────────────────────────────────────

os.makedirs(DIR_FOR_SAVING, exist_ok=True)


def get_local_ips() -> set[str]:
    ips = set()
    for addrs in psutil.net_if_addrs().values():
        for addr in addrs:
            if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                ips.add(addr.address)
    return ips


def find_best_interface() -> str | None:
    """
    Finds the Scapy interface that corresponds to the IP used for outbound traffic.
    On Windows, Scapy interface names are GUIDs, not 'Ethernet 2'.
    """
    # Determine the IP through which traffic is routed (default route)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        outbound_ip = s.getsockname()[0]
    finally:
        s.close()

    print(f"[*] Outbound traffic IP: {outbound_ip}")

    # Map IP -> psutil interface name
    psutil_iface = None
    for iface_name, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET and addr.address == outbound_ip:
                psutil_iface = iface_name
                break

    print(f"[*] psutil interface: {psutil_iface}")

    # Scapy on Windows uses different names (GUID) — we search by IP
    try:
        from scapy.arch.windows import get_windows_if_list
        ifaces = get_windows_if_list()
        for iface in ifaces:
            if outbound_ip in iface.get("ips", []):
                name = iface.get("name") or iface.get("description")
                print(f"[*] Scapy interface: {name}")
                return name
    except Exception as e:
        print(f"[!] get_windows_if_list error: {e}")

    # Fallback — try via conf.ifaces
    try:
        for iface_name, iface_obj in conf.ifaces.items():
            if hasattr(iface_obj, 'ip') and iface_obj.ip == outbound_ip:
                print(f"[*] Scapy interface (fallback): {iface_name}")
                return iface_name
    except Exception as e:
        print(f"[!] conf.ifaces error: {e}")

    print("[!] Failed to detect the interface automatically.")
    print("    Available Scapy interfaces:")
    for i in get_if_list():
        print(f"      {i}")
    return None


class PortMap:
    def __init__(self, target_apps):
        self.target_apps = target_apps
        self._map: dict[int, str] = {}
        self._lock = threading.Lock()

    def start(self):
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while True:
            temp = {}
            try:
                for conn in psutil.net_connections(kind='inet'):
                    if not conn.pid or not conn.laddr:
                        continue
                    try:
                        name = psutil.Process(conn.pid).name().lower()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                    for app in self.target_apps:
                        if app in name:
                            temp[conn.laddr.port] = app
                            break
            except psutil.AccessDenied:
                pass
            with self._lock:
                self._map = temp
            time.sleep(1)

    def lookup(self, port: int) -> str | None:
        with self._lock:
            return self._map.get(port)

    def snapshot(self):
        with self._lock:
            return dict(self._map)


class FlowCache:
    def __init__(self, ttl=120):
        self._cache = {}
        self._lock = threading.Lock()
        self._ttl = ttl

    def _key(self, si, di, sp, dp, pr):
        a, b = (si, sp), (di, dp)
        if a > b: a, b = b, a
        return (a, b, pr)

    def get(self, si, di, sp, dp, pr):
        k = self._key(si, di, sp, dp, pr)
        with self._lock:
            e = self._cache.get(k)
            if e and time.time() - e[1] < self._ttl:
                return e[0]
        return None

    def set(self, si, di, sp, dp, pr, app):
        k = self._key(si, di, sp, dp, pr)
        with self._lock:
            self._cache[k] = (app, time.time())


class WriterPool:
    def __init__(self):
        self._w = {}
        self._lock = threading.Lock()
        self._counts = defaultdict(int)

    def write(self, app, packet):
        date_str = datetime.now().strftime("%Y-%m-%d")
        with self._lock:
            writer, cur = self._w.get(app, (None, None))
            if writer is None or cur != date_str:
                if writer:
                    writer.close()
                path = os.path.join(DIR_FOR_SAVING, f"{app}_{date_str}.pcap")
                writer = PcapWriter(path, append=True, sync=True)
                self._w[app] = (writer, date_str)
                print(f"\n[+] File: {path}")
            writer.write(packet)
            self._counts[app] += 1

    def stats(self):
        with self._lock:
            return dict(self._counts)

    def close_all(self):
        with self._lock:
            for w, _ in self._w.values():
                try: w.close()
                except: pass


class AppSniffer:
    def __init__(self):
        self.local_ips = get_local_ips()
        self.port_map  = PortMap(TARGET_APPS)
        self.flow_cache = FlowCache()
        self.writers   = WriterPool()
        self._stop     = threading.Event()
        self._drops    = defaultdict(int)

    def _resolve_app(self, src_ip, dst_ip, sport, dport, proto):
        app = self.flow_cache.get(src_ip, dst_ip, sport, dport, proto)
        if app:
            return app

        if src_ip in self.local_ips:
            local_port = sport
        elif dst_ip in self.local_ips:
            local_port = dport
        else:
            self._drops['no_local_ip'] += 1
            return None

        app = self.port_map.lookup(local_port)
        if app:
            self.flow_cache.set(src_ip, dst_ip, sport, dport, proto, app)
        else:
            self._drops['port_unknown'] += 1
        return app

    def packet_handler(self, packet):
        if not packet.haslayer(IP):
            return
        ip = packet[IP]
        if packet.haslayer(TCP):
            l, proto = packet[TCP], "TCP"
        elif packet.haslayer(UDP):
            l, proto = packet[UDP], "UDP"
        else:
            return

        app = self._resolve_app(ip.src, ip.dst, l.sport, l.dport, proto)
        if app:
            self.writers.write(app, packet)

    def _stats_loop(self):
        while not self._stop.is_set():
            time.sleep(5)
            pm = self.port_map.snapshot()
            print(f"\r[STATS] saved={self.writers.stats()}  "
                  f"spotify_ports={list(pm.keys())}  "
                  f"dropped={dict(self._drops)}   ", end="", flush=True)

    def start(self):
        print(f"[*] Local IPs    : {self.local_ips}")

        iface = find_best_interface()
        if iface is None:
            print("\n[!] Manually enter the interface name from the list above and set:")
            print("    IFACE = 'interface_name'  in the code")
            return

        self.port_map.start()
        threading.Thread(target=self._stats_loop, daemon=True).start()
        time.sleep(2)

        pm = self.port_map.snapshot()
        print(f"[*] Found Spotify ports: {list(pm.keys())}")
        if not pm:
            print("[!] No ports found — play something on Spotify and try again.")

        sniff_thread = threading.Thread(
            target=lambda: sniff(
                iface=iface,
                filter="ip",
                prn=self.packet_handler,
                store=False,
                stop_filter=lambda _: self._stop.is_set()
            ),
            daemon=True
        )
        sniff_thread.start()
        print(f"[*] Sniffing on '{iface}'... (Press Ctrl+C to stop)\n")

        try:
            while sniff_thread.is_alive():
                sniff_thread.join(timeout=1)
        except KeyboardInterrupt:
            print("\n[*] Stopping...")
            self._stop.set()
            sniff_thread.join(timeout=5)
        finally:
            self.writers.close_all()
            print("[*] Done. Statistics:", self.writers.stats())


if __name__ == "__main__":
    AppSniffer().start()
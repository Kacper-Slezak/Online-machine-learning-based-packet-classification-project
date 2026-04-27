# capture_utils.py
import socket
import psutil
import threading
import time
import os
from datetime import datetime
from collections import defaultdict
from scapy.all import PcapWriter, conf, get_if_list

def get_local_ips() -> set[str]:
    ips = set()
    for addrs in psutil.net_if_addrs().values():
        for addr in addrs:
            if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                ips.add(addr.address)
    return ips

def find_best_interface() -> str | None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        outbound_ip = s.getsockname()[0]
    finally:
        s.close()
    
    try:
        from scapy.arch.windows import get_windows_if_list
        for iface in get_windows_if_list():
            if outbound_ip in iface.get("ips", []):
                return iface.get("name") or iface.get("description")
    except Exception:
        pass
        
    try:
        for iface_name, iface_obj in conf.ifaces.items():
            if getattr(iface_obj, "ip", None) == outbound_ip:
                return iface_name
    except Exception:
        pass
    return None

class PortMap:
    """Mapuje aktywne porty lokalne na nazwy procesów."""
    def __init__(self, target_apps: list[str]):
        self._target_apps = [a.lower() for a in target_apps]
        self._map = {}
        self._lock = threading.Lock()
        self._ready = threading.Event()

    def start(self):
        threading.Thread(target=self._loop, daemon=True, name="PortMap").start()

    def _loop(self):
        first = True
        while True:
            temp = {}
            try:
                for conn in psutil.net_connections(kind="inet"):
                    if conn.pid and conn.laddr:
                        try:
                            proc_name = psutil.Process(conn.pid).name().lower()
                            for app in self._target_apps:
                                if app in proc_name:
                                    temp[conn.laddr.port] = app
                                    break
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue
            except psutil.AccessDenied:
                pass
            with self._lock:
                self._map = temp
            if first:
                self._ready.set()
                first = False
            time.sleep(1)

    def wait_ready(self, timeout=5.0):
        self._ready.wait(timeout=timeout)

    def lookup(self, port: int) -> str | None:
        with self._lock:
            return self._map.get(port)

    def snapshot(self) -> dict:
        with self._lock:
            return dict(self._map)

class FlowCache:
    """Buforuje przepływy, by przyspieszyć przypisywanie aplikacji."""
    def __init__(self, ttl: float = 120):
        self._cache = {}
        self._lock = threading.Lock()
        self._ttl = ttl

    def _key(self, si, di, sp, dp, pr):
        a, b = (si, sp), (di, dp)
        return (min(a, b), max(a, b), pr)

    def get(self, si, di, sp, dp, pr):
        k = self._key(si, di, sp, dp, pr)
        with self._lock:
            entry = self._cache.get(k)
            if entry and (time.time() - entry[1]) < self._ttl:
                return entry[0]
        return None

    def set(self, si, di, sp, dp, pr, app: str):
        k = self._key(si, di, sp, dp, pr)
        with self._lock:
            self._cache[k] = (app, time.time())

    def flow_id(self, si, di, sp, dp, pr) -> str:
        a, b = min((si, sp), (di, dp)), max((si, sp), (di, dp))
        return f"{a[0]}:{a[1]}-{b[0]}:{b[1]}-{pr}"

class WriterPool:
    """Zarządza surowymi plikami PCAP."""
    def __init__(self, dir_for_saving="traffic_logs"):
        self.dir_for_saving = dir_for_saving
        self._writers = {}
        self._lock = threading.Lock()
        self._counts = defaultdict(int)

    def write(self, app: str, packet):
        date_str = datetime.now().strftime("%Y-%m-%d")
        with self._lock:
            writer, cur_date = self._writers.get(app, (None, None))
            if writer is None or cur_date != date_str:
                if writer:
                    writer.close()
                path = os.path.join(self.dir_for_saving, f"{app}_{date_str}.pcap")
                writer = PcapWriter(path, append=True, sync=True)
                self._writers[app] = (writer, date_str)
            
        writer.write(packet) # Zapis poza lockiem!
        with self._lock:
            self._counts[app] += 1

    def close_all(self):
        with self._lock:
            for writer, _ in self._writers.values():
                try: writer.close()
                except Exception: pass

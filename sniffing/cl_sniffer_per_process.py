"""
Network sniffer z ekstrakcją danych uczących dla modelu ML.

Zbiera:
  - surowy ruch (.pcap)  — do analizy w Wireshark
  - cechy pakietów (.csv) — gotowe do trenowania modelu
  - statystyki przepływów (.jsonl) — flow-level features

Wymagania:
    pip install scapy psutil
    Uruchamiaj jako Administrator (Windows) lub sudo (Linux/Mac)
"""

from __future__ import annotations

import csv
import json
import os
import socket
import threading
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path

import psutil
from scapy.all import PcapWriter, conf, get_if_list, sniff
from scapy.layers.inet import IP, TCP, UDP

# ─── Konfiguracja ──────────────────────────────────────────────────────────────

TARGET_APPS    = ["spotify"]
DIR_FOR_SAVING = "traffic_logs"
DEBUG          = True

# Cechy zapisywane do CSV (dane uczące)
CSV_FEATURES = [
    "timestamp",        # czas uniksowy (float)
    "app",              # nazwa aplikacji
    "direction",        # "out" / "in"
    "protocol",         # TCP / UDP
    "src_ip",
    "dst_ip",
    "sport",
    "dport",
    "pkt_len",          # długość całego pakietu IP
    "ip_ttl",
    "tcp_flags",        # bitmask flag TCP (0 dla UDP)
    "tcp_window",       # rozmiar okna TCP (0 dla UDP)
    "payload_len",      # długość payloadu (bez nagłówków)
    "inter_arrival_ms", # czas od poprzedniego pakietu danego flow [ms]
    "flow_id",          # unikalny identyfikator przepływu
]

# ──────────────────────────────────────────────────────────────────────────────

os.makedirs(DIR_FOR_SAVING, exist_ok=True)


# ─── Narzędzia sieciowe ────────────────────────────────────────────────────────

def get_local_ips() -> set[str]:
    ips: set[str] = set()
    for addrs in psutil.net_if_addrs().values():
        for addr in addrs:
            if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                ips.add(addr.address)
    return ips


def find_best_interface() -> str | None:
    """
    Zwraca nazwę interfejsu Scapy odpowiadającą trasie domyślnej.
    Na Windows nazwy to GUIDy, nie 'Ethernet 2'.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        outbound_ip = s.getsockname()[0]
    finally:
        s.close()

    print(f"[*] IP ruchu wychodzącego: {outbound_ip}")

    # Windows — szukamy po IP w liście Scapy
    try:
        from scapy.arch.windows import get_windows_if_list
        for iface in get_windows_if_list():
            if outbound_ip in iface.get("ips", []):
                name = iface.get("name") or iface.get("description")
                print(f"[*] Interfejs Scapy: {name}")
                return name
    except Exception as e:
        if DEBUG:
            print(f"[!] get_windows_if_list: {e}")

    # Fallback — conf.ifaces (Linux/Mac)
    try:
        for iface_name, iface_obj in conf.ifaces.items():
            if getattr(iface_obj, "ip", None) == outbound_ip:
                print(f"[*] Interfejs Scapy (fallback): {iface_name}")
                return iface_name
    except Exception as e:
        if DEBUG:
            print(f"[!] conf.ifaces: {e}")

    print("[!] Nie udało się automatycznie wykryć interfejsu.")
    print("    Dostępne interfejsy Scapy:")
    for i in get_if_list():
        print(f"      {i}")
    return None


# ─── PortMap ──────────────────────────────────────────────────────────────────

class PortMap:
    """Cyklicznie mapuje port lokalny -> nazwa aplikacji."""

    def __init__(self, target_apps: list[str]):
        self._target_apps = [a.lower() for a in target_apps]
        self._map: dict[int, str] = {}
        self._lock = threading.Lock()
        self._ready = threading.Event()   # sygnał: pierwsze wypełnienie gotowe

    def start(self):
        threading.Thread(target=self._loop, daemon=True, name="PortMap").start()

    def _loop(self):
        first = True
        while True:
            temp: dict[int, str] = {}
            try:
                for conn in psutil.net_connections(kind="inet"):
                    if not conn.pid or not conn.laddr:
                        continue
                    try:
                        proc_name = psutil.Process(conn.pid).name().lower()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                    for app in self._target_apps:
                        if app in proc_name:
                            temp[conn.laddr.port] = app
                            break
            except psutil.AccessDenied:
                pass

            with self._lock:
                self._map = temp

            if first:
                self._ready.set()
                first = False
            time.sleep(1)

    def wait_ready(self, timeout: float = 5.0):
        """Czeka na pierwsze wypełnienie mapy (bez sleep'owania w głównym wątku)."""
        self._ready.wait(timeout=timeout)

    def lookup(self, port: int) -> str | None:
        with self._lock:
            return self._map.get(port)

    def snapshot(self) -> dict[int, str]:
        with self._lock:
            return dict(self._map)


# ─── FlowCache ────────────────────────────────────────────────────────────────

class FlowCache:
    """
    Zapamiętuje przynależność przepływu do aplikacji przez `ttl` sekund.
    Klucz jest symetryczny (A→B == B→A).
    """

    def __init__(self, ttl: float = 120):
        self._cache: dict[tuple, tuple[str, float]] = {}
        self._lock  = threading.Lock()
        self._ttl   = ttl

    @staticmethod
    def _key(si: str, di: str, sp: int, dp: int, pr: str) -> tuple:
        # POPRAWKA: min/max gwarantuje stabilność klucza niezależnie od kierunku
        a, b = (si, sp), (di, dp)
        return (min(a, b), max(a, b), pr)

    def get(self, si, di, sp, dp, pr) -> str | None:
        k = self._key(si, di, sp, dp, pr)
        with self._lock:
            entry = self._cache.get(k)
            if entry and (time.time() - entry[1]) < self._ttl:
                return entry[0]
            if entry:
                del self._cache[k]
        return None

    def set(self, si, di, sp, dp, pr, app: str):
        k = self._key(si, di, sp, dp, pr)
        with self._lock:
            self._cache[k] = (app, time.time())

    def flow_id(self, si, di, sp, dp, pr) -> str:
        """Czytelny identyfikator przepływu — przydatny jako cecha ML."""
        a, b = (si, sp), (di, dp)
        a, b = min(a, b), max(a, b)
        return f"{a[0]}:{a[1]}-{b[0]}:{b[1]}-{pr}"


# ─── WriterPool ───────────────────────────────────────────────────────────────

class WriterPool:
    """
    Zarządza plikami PCAP z rotacją dobową.
    POPRAWKA: lock trzymany tylko podczas otwierania pliku, nie podczas zapisu.
    """

    def __init__(self):
        self._writers: dict[str, tuple[PcapWriter, str]] = {}
        self._lock   = threading.Lock()
        self._counts : dict[str, int] = defaultdict(int)

    def _get_writer(self, app: str) -> PcapWriter:
        """Zwraca (ewentualnie nowo otwarty) writer dla danej apki i dnia."""
        date_str = datetime.now().strftime("%Y-%m-%d")
        with self._lock:
            writer, cur_date = self._writers.get(app, (None, None))
            if writer is None or cur_date != date_str:
                if writer is not None:
                    try:
                        writer.close()
                    except Exception:
                        pass
                path = os.path.join(DIR_FOR_SAVING, f"{app}_{date_str}.pcap")
                writer = PcapWriter(path, append=True, sync=True)
                self._writers[app] = (writer, date_str)
                print(f"\n[+] Nowy plik PCAP: {path}")
            return writer

    def write(self, app: str, packet):
        writer = self._get_writer(app)
        writer.write(packet)       # zapis POZA lockiem — nie blokuje innych wątków
        with self._lock:
            self._counts[app] += 1

    def stats(self) -> dict[str, int]:
        with self._lock:
            return dict(self._counts)

    def close_all(self):
        with self._lock:
            for writer, _ in self._writers.values():
                try:
                    writer.close()
                except Exception:   # POPRAWKA: nie łapiemy BaseException
                    pass
            self._writers.clear()


# ─── TrainingDataWriter ───────────────────────────────────────────────────────

class TrainingDataWriter:
    """
    Zapisuje cechy pakietów do pliku CSV (dane uczące) i przepływów do JSONL.

    CSV — jeden wiersz = jeden pakiet, cechy podane w CSV_FEATURES.
    JSONL — jeden wiersz = zakończony przepływ, statystyki flow-level.
    """

    def __init__(self):
        self._csv_files:  dict[str, tuple] = {}   # app -> (file_obj, csv.DictWriter)
        self._lock = threading.Lock()
        # last_ts[flow_id] = timestamp ostatniego pakietu (do inter-arrival)
        self._last_ts: dict[str, float] = {}
        # statystyki live per flow
        self._flows: dict[str, dict] = defaultdict(lambda: {
            "pkt_count": 0,
            "total_bytes": 0,
            "start_ts": None,
            "last_ts": None,
            "app": None,
        })

    def _get_csv_writer(self, app: str):
        """Zwraca (file, DictWriter) dla danej apki, tworząc plik jeśli trzeba."""
        date_str = datetime.now().strftime("%Y-%m-%d")
        with self._lock:
            entry = self._csv_files.get(app)
            if entry is None or entry[2] != date_str:
                if entry:
                    entry[0].close()
                path = os.path.join(DIR_FOR_SAVING, f"{app}_{date_str}_features.csv")
                is_new = not Path(path).exists()
                f = open(path, "a", newline="", encoding="utf-8")
                writer = csv.DictWriter(f, fieldnames=CSV_FEATURES)
                if is_new:
                    writer.writeheader()
                    print(f"\n[+] Nowy plik CSV: {path}")
                self._csv_files[app] = (f, writer, date_str)
                return f, writer
            return entry[0], entry[1]

    def record(
        self,
        app: str,
        direction: str,
        protocol: str,
        src_ip: str,
        dst_ip: str,
        sport: int,
        dport: int,
        packet,
        flow_id: str,
    ):
        now = time.time()
        ip_layer = packet[IP]

        # ── cechy warstwy transportowej ──
        if protocol == "TCP":
            t = packet[TCP]
            tcp_flags  = int(t.flags)
            tcp_window = int(t.window)
            payload    = bytes(t.payload)
        else:
            t = packet[UDP]
            tcp_flags  = 0
            tcp_window = 0
            payload    = bytes(t.payload)

        # inter-arrival time
        last = self._last_ts.get(flow_id)
        inter_ms = round((now - last) * 1000, 3) if last is not None else 0.0
        self._last_ts[flow_id] = now

        row = {
            "timestamp":        round(now, 6),
            "app":              app,
            "direction":        direction,
            "protocol":         protocol,
            "src_ip":           src_ip,
            "dst_ip":           dst_ip,
            "sport":            sport,
            "dport":            dport,
            "pkt_len":          len(ip_layer),
            "ip_ttl":           ip_layer.ttl,
            "tcp_flags":        tcp_flags,
            "tcp_window":       tcp_window,
            "payload_len":      len(payload),
            "inter_arrival_ms": inter_ms,
            "flow_id":          flow_id,
        }

        _, csv_writer = self._get_csv_writer(app)
        csv_writer.writerow(row)

        # aktualizacja statystyk przepływu
        fl = self._flows[flow_id]
        fl["pkt_count"]   += 1
        fl["total_bytes"] += len(ip_layer)
        fl["app"]          = app
        if fl["start_ts"] is None:
            fl["start_ts"] = now
        fl["last_ts"] = now

    def flush_flows(self):
        """Zapisuje zagregowane statystyki przepływów do pliku JSONL."""
        date_str = datetime.now().strftime("%Y-%m-%d")
        path = os.path.join(DIR_FOR_SAVING, f"flows_{date_str}.jsonl")
        with self._lock:
            flows_snap = dict(self._flows)

        with open(path, "a", encoding="utf-8") as f:
            for fid, data in flows_snap.items():
                if data["pkt_count"] == 0:
                    continue
                duration = (
                    round(data["last_ts"] - data["start_ts"], 3)
                    if data["start_ts"] and data["last_ts"]
                    else 0.0
                )
                record = {
                    "flow_id":     fid,
                    "app":         data["app"],
                    "pkt_count":   data["pkt_count"],
                    "total_bytes": data["total_bytes"],
                    "duration_s":  duration,
                    "avg_pps":     round(data["pkt_count"] / duration, 2) if duration > 0 else 0,
                    "saved_at":    datetime.now().isoformat(),
                }
                f.write(json.dumps(record, ensure_ascii=False) + "\n")

    def close_all(self):
        self.flush_flows()
        with self._lock:
            for f, _, _ in self._csv_files.values():
                try:
                    f.close()
                except Exception:
                    pass
            self._csv_files.clear()


# ─── AppSniffer ───────────────────────────────────────────────────────────────

class AppSniffer:
    def __init__(self):
        self.local_ips   = get_local_ips()
        self.port_map    = PortMap(TARGET_APPS)
        self.flow_cache  = FlowCache()
        self.writers     = WriterPool()
        self.train_writer = TrainingDataWriter()
        self._stop       = threading.Event()
        self._drops: dict[str, int] = defaultdict(int)
        self._sniff_thread: threading.Thread | None = None  # POPRAWKA: inicjalizacja przed try

    def _resolve_app(
        self,
        src_ip: str, dst_ip: str,
        sport: int,  dport: int,
        proto: str,
    ) -> str | None:
        app = self.flow_cache.get(src_ip, dst_ip, sport, dport, proto)
        if app:
            return app

        if src_ip in self.local_ips:
            local_port = sport
        elif dst_ip in self.local_ips:
            local_port = dport
        else:
            self._drops["no_local_ip"] += 1
            return None

        app = self.port_map.lookup(local_port)
        if app:
            self.flow_cache.set(src_ip, dst_ip, sport, dport, proto, app)
        else:
            self._drops["port_unknown"] += 1
        return app

    def packet_handler(self, packet):
        if not packet.haslayer(IP):
            return
        ip = packet[IP]

        if packet.haslayer(TCP):
            layer, proto = packet[TCP], "TCP"
        elif packet.haslayer(UDP):
            layer, proto = packet[UDP], "UDP"
        else:
            return

        src_ip, dst_ip = ip.src, ip.dst
        sport,  dport  = layer.sport, layer.dport

        app = self._resolve_app(src_ip, dst_ip, sport, dport, proto)
        if not app:
            return

        direction = "out" if src_ip in self.local_ips else "in"
        flow_id   = self.flow_cache.flow_id(src_ip, dst_ip, sport, dport, proto)

        # zapis surowego PCAP
        self.writers.write(app, packet)

        # zapis cech do CSV (dane uczące)
        self.train_writer.record(
            app=app,
            direction=direction,
            protocol=proto,
            src_ip=src_ip,
            dst_ip=dst_ip,
            sport=sport,
            dport=dport,
            packet=packet,
            flow_id=flow_id,
        )

    def _stats_loop(self):
        """Co 5 sekund wyświetla statystyki i zapisuje flow JSONL."""
        while not self._stop.is_set():
            time.sleep(5)
            pm = self.port_map.snapshot()
            print(
                f"\r[STATS] zapisane={self.writers.stats()}  "
                f"porty_spotify={list(pm.keys())}  "
                f"odrzucone={dict(self._drops)}   ",
                end="",
                flush=True,
            )
            self.train_writer.flush_flows()

    def start(self):
        print(f"[*] Lokalne IP: {self.local_ips}")

        iface = find_best_interface()
        if iface is None:
            print("\n[!] Ustaw ręcznie nazwę interfejsu w kodzie (IFACE = '...')")
            return

        self.port_map.start()
        print("[*] Czekam na mapę portów...", end=" ", flush=True)
        self.port_map.wait_ready(timeout=5.0)   # POPRAWKA: Event zamiast sleep(2)
        print("OK")

        pm = self.port_map.snapshot()
        print(f"[*] Znalezione porty Spotify: {list(pm.keys())}")
        if not pm:
            print("[!] Brak portów — uruchom Spotify i odtwórz coś, potem spróbuj ponownie.")

        threading.Thread(target=self._stats_loop, daemon=True, name="Stats").start()

        # POPRAWKA: inicjalizujemy przed try, żeby finally zawsze było bezpieczne
        self._sniff_thread = threading.Thread(
            target=lambda: sniff(
                iface=iface,
                filter="ip",
                prn=self.packet_handler,
                store=False,
                stop_filter=lambda _: self._stop.is_set(),
            ),
            daemon=True,
            name="Sniffer",
        )
        self._sniff_thread.start()
        print(f"[*] Sniffuję na '{iface}'... (Ctrl+C = stop)\n")

        try:
            while self._sniff_thread.is_alive():
                self._sniff_thread.join(timeout=1)
        except KeyboardInterrupt:
            print("\n[*] Zatrzymuję...")
            self._stop.set()
            self._sniff_thread.join(timeout=5)
        finally:
            self.writers.close_all()
            self.train_writer.close_all()
            print("[*] Gotowe. Statystyki:", self.writers.stats())
            print(f"[*] Dane uczące zapisane w: {DIR_FOR_SAVING}/")


if __name__ == "__main__":
    AppSniffer().start()
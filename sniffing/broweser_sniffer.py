"""
browser_sniffer.py — Etykietowanie ruchu przeglądarkowego

Dwa mechanizmy działające równolegle:

1. SNI (Server Name Indication)
   - W każdym połączeniu TLS przeglądarka wysyła niezaszyfrowaną nazwę domeny
     w pakiecie ClientHello (zanim zacznie szyfrowanie).
   - Scapy parsuje raw bajty i wyciąga SNI → wiemy dokładnie z jaką domeną
     rozmawia przeglądarka.
   - Działa dla: Chrome, Firefox, Edge, Spotify webowy, prawie wszystko HTTPS.
   - NIE działa dla: QUIC/HTTP3 (ten protokół szyfruje ClientHello).

2. DNS Correlation
   - Łapiemy odpowiedzi DNS → zapisujemy IP → nazwa_domeny.
   - Gdy pakiet idzie do tego IP, etykietujemy po domenie.
   - Uzupełnienie dla QUIC i przypadków gdzie SNI nie jest dostępne.
   - Słabsze: CDN-y (np. Akamai, Cloudflare) obsługują setki domen pod jednym IP.

Razem: SNI ma priorytet, DNS jako fallback.
"""

from scapy.all import sniff, PcapWriter, Raw
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR, DNSRR
import psutil
import threading
import time
import os
import socket
import struct
from datetime import datetime
from collections import defaultdict

# ─── Konfiguracja ─────────────────────────────────────────────────────────────

# Mapowanie domen → etykieta aplikacji
DOMAIN_TO_LABEL = {
    # Streaming
    "youtube.com":        "YouTube",
    "googlevideo.com":    "YouTube",       # serwery CDN YouTube
    "ytimg.com":          "YouTube",
    "netflix.com":        "Netflix",
    "nflxvideo.net":      "Netflix",
    "twitch.tv":          "Twitch",
    "twitchsvc.net":      "Twitch",
    # Komunikacja
    "teams.microsoft.com":   "Teams",
    "teams.live.com":        "Teams",
    "zoom.us":               "Zoom",
    "zoomgov.com":           "Zoom",
    "slack.com":             "Slack",
    "slack-edge.com":        "Slack",
    # Muzyka
    "spotify.com":           "Spotify",
    "scdn.co":               "Spotify",    # CDN Spotify
    "spotifycdn.com":        "Spotify",
    # Inne
    "github.com":            "GitHub",
    "discord.com":           "Discord",
    "discordapp.com":        "Discord",
}

DIR_FOR_SAVING = "traffic_logs"
DNS_CACHE_TTL  = 300   # sekundy — jak długo pamiętamy IP→domena z DNS
SNI_CACHE_TTL  = 120   # sekundy — jak długo pamiętamy SNI dla danego flow

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
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        outbound_ip = s.getsockname()[0]
    finally:
        s.close()
    print(f"[*] IP ruchu wychodzącego: {outbound_ip}")
    try:
        from scapy.arch.windows import get_windows_if_list
        for iface in get_windows_if_list():
            if outbound_ip in iface.get("ips", []):
                name = iface.get("name") or iface.get("description")
                print(f"[*] Interfejs Scapy: {name}")
                return name
    except Exception:
        pass
    from scapy.all import conf
    for iface_name, iface_obj in conf.ifaces.items():
        if hasattr(iface_obj, 'ip') and iface_obj.ip == outbound_ip:
            return iface_name
    return None


def domain_to_label(hostname: str) -> str | None:
    """Dopasowuje hostname do etykiety — sprawdza suffix domeny."""
    hostname = hostname.lower().rstrip(".")
    for domain, label in DOMAIN_TO_LABEL.items():
        if hostname == domain or hostname.endswith("." + domain):
            return label
    return None


# ─── SNI Parser ───────────────────────────────────────────────────────────────

def extract_sni(payload: bytes) -> str | None:
    """
    Parsuje raw bajty TCP i wyciąga SNI z TLS ClientHello.
    
    Struktura TLS ClientHello (uproszczona):
    [0]      = 0x16 (TLS Handshake)
    [1-2]    = wersja TLS
    [3-4]    = długość rekordu
    [5]      = 0x01 (ClientHello)
    ...
    Szukamy extension type 0x0000 (SNI) i wyciągamy nazwę hosta.
    """
    try:
        # Sprawdź czy to TLS Handshake (0x16) i ClientHello (0x01)
        if len(payload) < 6 or payload[0] != 0x16 or payload[5] != 0x01:
            return None

        # Pomiń nagłówek rekordu TLS (5B) + typ handshake (1B)
        pos = 6
        # Długość ClientHello (3 bajty big-endian)
        if pos + 3 > len(payload):
            return None
        ch_len = struct.unpack("!I", b'\x00' + payload[pos:pos+3])[0]
        pos += 3

        # Wersja (2B) + Random (32B) = 34 bajty do pominięcia
        pos += 34

        # Session ID
        if pos >= len(payload): return None
        session_id_len = payload[pos]; pos += 1 + session_id_len

        # Cipher Suites
        if pos + 2 > len(payload): return None
        cs_len = struct.unpack("!H", payload[pos:pos+2])[0]; pos += 2 + cs_len

        # Compression Methods
        if pos >= len(payload): return None
        cm_len = payload[pos]; pos += 1 + cm_len

        # Extensions length
        if pos + 2 > len(payload): return None
        ext_len = struct.unpack("!H", payload[pos:pos+2])[0]; pos += 2

        ext_end = pos + ext_len
        while pos + 4 <= ext_end and pos + 4 <= len(payload):
            ext_type = struct.unpack("!H", payload[pos:pos+2])[0]; pos += 2
            ext_data_len = struct.unpack("!H", payload[pos:pos+2])[0]; pos += 2

            if ext_type == 0x0000:  # SNI extension
                # list_len (2B) + type (1B) + name_len (2B) + name
                if pos + 5 > len(payload): return None
                pos += 2  # list_len
                pos += 1  # name_type (0 = host_name)
                name_len = struct.unpack("!H", payload[pos:pos+2])[0]; pos += 2
                return payload[pos:pos+name_len].decode("utf-8", errors="ignore")

            pos += ext_data_len

    except Exception:
        pass
    return None


# ─── DNS Cache ────────────────────────────────────────────────────────────────

class DNSCache:
    """IP → (label, timestamp). Budowany z odpowiedzi DNS."""

    def __init__(self, ttl=DNS_CACHE_TTL):
        self._map: dict[str, tuple[str, float]] = {}
        self._lock = threading.Lock()
        self._ttl = ttl
        self._hits = 0
        self._total_records = 0

    def add_from_packet(self, packet):
        """Parsuje odpowiedź DNS i zapisuje IP→label."""
        if not packet.haslayer(DNS):
            return
        dns = packet[DNS]
        if dns.qr != 1:  # tylko odpowiedzi (qr=1)
            return

        # Przejdź przez wszystkie rekordy odpowiedzi
        for i in range(dns.ancount):
            try:
                rr = dns.an[i]
                if rr.type != 1:  # tylko A records (IPv4)
                    continue
                name = rr.rrname.decode("utf-8", errors="ignore").rstrip(".")
                ip   = rr.rdata
                label = domain_to_label(name)
                if label:
                    with self._lock:
                        self._map[ip] = (label, time.time())
                        self._total_records += 1
            except Exception:
                continue

    def lookup(self, ip: str) -> str | None:
        with self._lock:
            entry = self._map.get(ip)
            if entry:
                label, ts = entry
                if time.time() - ts < self._ttl:
                    self._hits += 1
                    return label
                del self._map[ip]
        return None

    def stats(self):
        with self._lock:
            return {"records": len(self._map), "total_seen": self._total_records, "hits": self._hits}


# ─── Flow → SNI cache ─────────────────────────────────────────────────────────

class FlowSNICache:
    """Zapamiętuje SNI dla danego flow (src_ip, dst_ip, dst_port)."""

    def __init__(self, ttl=SNI_CACHE_TTL):
        self._cache: dict[tuple, tuple[str, float]] = {}
        self._lock = threading.Lock()
        self._ttl = ttl

    def _key(self, src_ip, dst_ip, dport):
        return (src_ip, dst_ip, dport)

    def get(self, src_ip, dst_ip, dport) -> str | None:
        k = self._key(src_ip, dst_ip, dport)
        with self._lock:
            e = self._cache.get(k)
            if e and time.time() - e[1] < self._ttl:
                return e[0]
        return None

    def set(self, src_ip, dst_ip, dport, label: str):
        k = self._key(src_ip, dst_ip, dport)
        with self._lock:
            self._cache[k] = (label, time.time())


# ─── Writer Pool ──────────────────────────────────────────────────────────────

class WriterPool:
    def __init__(self):
        self._w: dict[str, tuple[PcapWriter, str]] = {}
        self._lock = threading.Lock()
        self._counts: dict[str, int] = defaultdict(int)

    def write(self, label: str, packet):
        date_str = datetime.now().strftime("%Y-%m-%d")
        with self._lock:
            writer, cur = self._w.get(label, (None, None))
            if writer is None or cur != date_str:
                if writer: writer.close()
                safe_name = label.replace(" ", "_").replace("/", "_")
                path = os.path.join(DIR_FOR_SAVING, f"{safe_name}_{date_str}.pcap")
                writer = PcapWriter(path, append=True, sync=True)
                self._w[label] = (writer, date_str)
                print(f"\n[+] Nowy plik: {path}")
            writer.write(packet)
            self._counts[label] += 1

    def stats(self):
        with self._lock:
            return dict(self._counts)

    def close_all(self):
        with self._lock:
            for w, _ in self._w.values():
                try: w.close()
                except: pass


# ─── Główny Sniffer ───────────────────────────────────────────────────────────

class BrowserSniffer:
    def __init__(self):
        self.local_ips   = get_local_ips()
        self.dns_cache   = DNSCache()
        self.sni_cache   = FlowSNICache()
        self.writers     = WriterPool()
        self._stop       = threading.Event()
        self._sni_found  = 0
        self._dns_found  = 0
        self._unlabeled  = 0

    def packet_handler(self, packet):
        if not packet.haslayer(IP):
            return

        ip = packet[IP]

        # ── DNS: buduj cache IP→domena ────────────────────────────────────────
        if packet.haslayer(DNS):
            self.dns_cache.add_from_packet(packet)
            # DNS pakiety zwykle nie mają sensu zapisywać per-aplikację,
            # ale możesz odkomentować jeśli chcesz:
            # self.writers.write("DNS", packet)
            return

        # ── Dalej tylko TCP/UDP ───────────────────────────────────────────────
        if packet.haslayer(TCP):
            l, proto = packet[TCP], "TCP"
        elif packet.haslayer(UDP):
            l, proto = packet[UDP], "UDP"
        else:
            return

        src_ip, dst_ip = ip.src, ip.dst
        sport, dport   = l.sport, l.dport

        label = None

        # ── Metoda 1: SNI z TLS ClientHello ──────────────────────────────────
        if proto == "TCP" and dport == 443 and packet.haslayer(Raw):
            payload = bytes(packet[Raw])
            sni = extract_sni(payload)
            if sni:
                label = domain_to_label(sni)
                if label:
                    # Zapamiętaj SNI dla tego flow — kolejne pakiety tego samego
                    # połączenia nie będą miały ClientHello, więc używamy cache
                    self.sni_cache.set(src_ip, dst_ip, dport, label)
                    self._sni_found += 1

        # ── Metoda 2: Flow cache z SNI (kolejne pakiety tego samego conn.) ────
        if label is None:
            label = self.sni_cache.get(src_ip, dst_ip, dport)
            if label is None:
                label = self.sni_cache.get(dst_ip, src_ip, sport)

        # ── Metoda 3: DNS correlation — po IP docelowym ───────────────────────
        if label is None:
            # Remote IP = ten który NIE jest lokalny
            remote_ip = dst_ip if src_ip in self.local_ips else src_ip
            label = self.dns_cache.lookup(remote_ip)
            if label:
                self._dns_found += 1

        if label:
            self.writers.write(label, packet)
        else:
            self._unlabeled += 1

    def _stats_loop(self):
        while not self._stop.is_set():
            time.sleep(10)
            print(f"\n[STATS] zapisane={self.writers.stats()} | "
                  f"SNI={self._sni_found} DNS={self._dns_found} "
                  f"bez_etykiety={self._unlabeled} | "
                  f"dns_cache={self.dns_cache.stats()}")

    def start(self):
        print(f"[*] Lokalne IP : {self.local_ips}")
        print(f"[*] Śledzone   : {list(DOMAIN_TO_LABEL.values())}")
        print(f"[*] Zapis do   : {DIR_FOR_SAVING}/")

        iface = find_best_interface()
        if iface is None:
            print("[!] Nie wykryto interfejsu automatycznie.")
            return

        threading.Thread(target=self._stats_loop, daemon=True).start()

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
        print(f"[*] Sniffing na '{iface}'... (Ctrl+C aby zatrzymać)\n")
        print("[*] TIP: Otwórz YouTube/Netflix w przeglądarce — SNI zadziała")
        print("         przy pierwszym pakiecie nowego połączenia.\n")

        try:
            while sniff_thread.is_alive():
                sniff_thread.join(timeout=1)
        except KeyboardInterrupt:
            print("\n[*] Zatrzymuję...")
            self._stop.set()
            sniff_thread.join(timeout=5)
        finally:
            self.writers.close_all()
            print("[*] Koniec. Statystyki:", self.writers.stats())


if __name__ == "__main__":
    BrowserSniffer().start()
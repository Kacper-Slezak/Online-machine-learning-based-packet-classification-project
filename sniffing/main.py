# main.py
import os
import threading
import time
from collections import defaultdict
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

from capture_utils import get_local_ips, find_best_interface, PortMap, FlowCache, WriterPool
from feature_extractor import FeatureExtractor

# --- Konfiguracja ---
TARGET_APPS = ["spotify", "teams", "chrome"]  # Zdefiniuj co nas interesuje do nauki
DIR_FOR_SAVING = "traffic_logs"
os.makedirs(DIR_FOR_SAVING, exist_ok=True)

class MainSniffer:
    def __init__(self):
        self.local_ips = get_local_ips()
        self.port_map = PortMap(TARGET_APPS)
        self.flow_cache = FlowCache()
        self.pcap_writer = WriterPool(DIR_FOR_SAVING)
        self.feature_extractor = FeatureExtractor(DIR_FOR_SAVING)
        
        self._stop = threading.Event()
        self._drops = defaultdict(int)

        # PRZYSZŁOŚĆ: self.model = pickle.load(open("random_forest.pkl", "rb"))

    def _resolve_app(self, src_ip, dst_ip, sport, dport, proto):
        app = self.flow_cache.get(src_ip, dst_ip, sport, dport, proto)
        if app: return app

        local_port = sport if src_ip in self.local_ips else dport if dst_ip in self.local_ips else None
        if not local_port:
            return None

        app = self.port_map.lookup(local_port)
        if app:
            self.flow_cache.set(src_ip, dst_ip, sport, dport, proto, app)
        return app

    def packet_handler(self, packet):
        if not packet.haslayer(IP): return
        
        if packet.haslayer(TCP): proto = "TCP"
        elif packet.haslayer(UDP): proto = "UDP"
        else: return

        ip = packet[IP]
        layer = packet[proto]
        
        # 1. Określamy do jakiej aplikacji należy pakiet (Tylko do fazy nauki/scrapowania!)
        app = self._resolve_app(ip.src, ip.dst, layer.sport, layer.dport, proto)
        if not app: return

        direction = "out" if ip.src in self.local_ips else "in"
        flow_id = self.flow_cache.flow_id(ip.src, ip.dst, layer.sport, layer.dport, proto)

        # 2. Zapis surowego PCAP (można wyłączyć w klasyfikacji online)
        self.pcap_writer.write(app, packet)

        # 3. Ekstrakcja cech - Magia ML!
        features = self.feature_extractor.extract_features(
            app=app, direction=direction, protocol=proto, packet=packet, flow_id=flow_id
        )

        # 4. Zapis do CSV (Tworzenie zbioru treningowego)
        self.feature_extractor.save_to_csv(features)

        # -----------------------------------------------------------------------------
        # GOTOWOŚĆ NA KLASYFIKACJĘ ONLINE (DO WDROŻENIA PÓŹNIEJ):
        # -----------------------------------------------------------------------------
        # Jeśli miałbyś załadowany model, tutaj pominąłbyś resolve_app (bo nie znasz 
        # jeszcze appki), wyciągnął cechy i przekazał do modelu:
        #
        # ml_input_vector = [ features["pkt_len"], features["inter_arrival_ms"], features["tcp_flags"], ... ]
        # predicted_app = self.model.predict([ml_input_vector])[0]
        # print(f"Model wykrył ruch: {predicted_app} (Wierność: ...)")
        # -----------------------------------------------------------------------------

    def start(self):
        iface = find_best_interface()
        if not iface:
            print("[!] Nie wykryto interfejsu.")
            return

        print(f"[*] Sniffuję na '{iface}'...")
        self.port_map.start()
        self.port_map.wait_ready()

        sniff_thread = threading.Thread(
            target=lambda: sniff(iface=iface, filter="ip", prn=self.packet_handler, store=False, stop_filter=lambda _: self._stop.is_set()),
            daemon=True
        )
        sniff_thread.start()

        try:
            while sniff_thread.is_alive():
                sniff_thread.join(1)
        except KeyboardInterrupt:
            print("\n[*] Zatrzymywanie...")
            self._stop.set()
        finally:
            self.pcap_writer.close_all()
            self.feature_extractor.close_all()
            print("[*] Zapisano dane treningowe.")

if __name__ == "__main__":
    MainSniffer().start()

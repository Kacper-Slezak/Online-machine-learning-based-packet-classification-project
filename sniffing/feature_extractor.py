import csv
import time
import os
from scapy.layers.inet import IP, TCP, UDP

CSV_FEATURES = [
    "timestamp", "app", "direction", "protocol", "src_ip", "dst_ip",
    "sport", "dport", "pkt_len", "ip_ttl", "tcp_flags", "tcp_window",
    "payload_len", "inter_arrival_ms", "flow_id"
]

class FeatureExtractor:
    """Przetwarza pakiety na zestawy cech gotowe do nauki modelu (CSV/Online ML)"""
    def __init__(self, dir_for_saving="traffic_logs"):
        self.dir_for_saving = dir_for_saving
        self._csv_files = {}
        self._last_ts = {}

    def extract_features(self, app, direction, protocol, packet, flow_id):
        """Kluczowa funkcja: zamienia pakiet na słownik cech dla ML."""
        now = time.time()
        ip_layer = packet[IP]

        if protocol == "TCP":
            t = packet[TCP]
            tcp_flags = int(t.flags)
            tcp_window = int(t.window)
            payload_len = len(bytes(t.payload))
        else:
            t = packet[UDP]
            tcp_flags = 0
            tcp_window = 0
            payload_len = len(bytes(t.payload))

        last = self._last_ts.get(flow_id)
        inter_ms = round((now - last) * 1000, 3) if last is not None else 0.0
        self._last_ts[flow_id] = now

        features = {
            "timestamp": round(now, 6),
            "app": app,
            "direction": direction,
            "protocol": protocol,
            "src_ip": ip_layer.src,
            "dst_ip": ip_layer.dst,
            "sport": packet[TCP].sport if protocol == "TCP" else packet[UDP].sport,
            "dport": packet[TCP].dport if protocol == "TCP" else packet[UDP].dport,
            "pkt_len": len(ip_layer),
            "ip_ttl": ip_layer.ttl,
            "tcp_flags": tcp_flags,
            "tcp_window": tcp_window,
            "payload_len": payload_len,
            "inter_arrival_ms": inter_ms,
            "flow_id": flow_id,
        }
        return features

    def save_to_csv(self, features: dict):
        """Zapisuje cechy do odpowiedniego pliku CSV."""
        app = features["app"]
        date_str = time.strftime("%Y-%m-%d")
        
        entry = self._csv_files.get(app)
        if entry is None or entry[2] != date_str:
            if entry: entry[0].close()
            path = os.path.join(self.dir_for_saving, f"{app}_{date_str}_features.csv")
            is_new = not os.path.exists(path)
            f = open(path, "a", newline="", encoding="utf-8")
            writer = csv.DictWriter(f, fieldnames=CSV_FEATURES)
            if is_new: writer.writeheader()
            self._csv_files[app] = (f, writer, date_str)
            entry = self._csv_files[app]

        entry[1].writerow(features)

    def close_all(self):
        for f, _, _ in self._csv_files.values():
            try: f.close()
            except Exception: pass

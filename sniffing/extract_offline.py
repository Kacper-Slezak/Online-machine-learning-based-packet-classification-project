import os
import glob
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
from feature_extractor import FeatureExtractor

# --- KONFIGURACJA ---
PCAP_DIR = "traffic_logs"
OUTPUT_DIR = "offline_features_csv"

# BARDZO WAŻNE: Podaj adres(y) IP maszyny, na której zbierano PCAP-y!
# Bez tego skrypt nie będzie wiedział, które pakiety to ruch wychodzący ("out"), 
# a które przychodzący ("in").
OLD_LOCAL_IPS = {"192.168.1.100", "10.0.0.5"} 
# --------------------

def get_flow_id(si, di, sp, dp, pr):
    """Pomocnicza funkcja do unikalnego oznaczania przepływów."""
    a, b = min((si, sp), (di, dp)), max((si, sp), (di, dp))
    return f"{a[0]}:{a[1]}-{b[0]}:{b[1]}-{pr}"

def process_pcap_batch():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    extractor = FeatureExtractor(dir_for_saving=OUTPUT_DIR)

    # Szukamy wszystkich plików PCAP w folderze
    pcap_files = glob.glob(os.path.join(PCAP_DIR, "*.pcap"))
    
    if not pcap_files:
        print(f"[!] Nie znaleziono żadnych plików .pcap w folderze {PCAP_DIR}")
        return

    print(f"[*] Znaleziono {len(pcap_files)} plików PCAP do przetworzenia.")

    for pcap_path in pcap_files:
        # Wyciągamy nazwę aplikacji z nazwy pliku (np. "spotify_2023...pcap" -> "spotify")
        filename = os.path.basename(pcap_path)
        app_label = filename.split('_')[0].lower()
        
        print(f"\n[>] Przetwarzanie: {filename} (Etykieta: {app_label})")

        # Zmienne liczące postęp dla danego pliku
        stats = {"processed": 0, "skipped": 0}

        def handle_offline_packet(packet):
            # Filtrujemy tylko pakiety IP (TCP/UDP)
            if not packet.haslayer(IP):
                stats["skipped"] += 1
                return
                
            if packet.haslayer(TCP): 
                proto = "TCP"
                layer = packet[TCP]
            elif packet.haslayer(UDP): 
                proto = "UDP"
                layer = packet[UDP]
            else: 
                stats["skipped"] += 1
                return

            ip = packet[IP]
            
            # Odtwarzamy kierunek ruchu
            direction = "out" if ip.src in OLD_LOCAL_IPS else "in"
            
            # Generujemy identyfikator przepływu
            flow_id = get_flow_id(ip.src, ip.dst, layer.sport, layer.dport, proto)

            # Wyciągamy cechy korzystając z naszego zmodularyzowanego kodu
            features = extractor.extract_features(
                app=app_label, 
                direction=direction, 
                protocol=proto, 
                packet=packet, 
                flow_id=flow_id
            )

            # Zapis do CSV
            extractor.save_to_csv(features)
            stats["processed"] += 1

        # Magia Scapy - czytanie z pliku zamiast z karty sieciowej
        sniff(offline=pcap_path, prn=handle_offline_packet, store=False)
        
        print(f"    Zakończono. Pakietów przetworzonych: {stats['processed']}, Pominiętych: {stats['skipped']}")

    # Zamykamy wszystkie otwarte pliki CSV na koniec pracy
    extractor.close_all()
    print(f"\n[*] Sukces! Wszystkie cechy zostały zapisane w folderze: {OUTPUT_DIR}")

if __name__ == "__main__":
    process_pcap_batch()

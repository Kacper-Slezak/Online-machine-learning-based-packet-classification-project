import os
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
from feature_extractor import FeatureExtractor  # Twój moduł z poprzedniego kroku

def process_pcap_offline(pcap_path, app_label, local_ips):
    print(f"[*] Przetwarzanie pliku: {pcap_path} (Etykieta: {app_label})")
    
    # Inicjujemy nasz ekstraktor cech
    extractor = FeatureExtractor(dir_for_saving="extracted_features_offline")
    os.makedirs("extracted_features_offline", exist_ok=True)
    
    # Prosty bufor, by wyliczyć flow_id (identyfikator przepływu)
    def get_flow_id(si, di, sp, dp, pr):
        a, b = min((si, sp), (di, dp)), max((si, sp), (di, dp))
        return f"{a[0]}:{a[1]}-{b[0]}:{b[1]}-{pr}"

    # Funkcja, która odpali się dla każdego pakietu w pliku PCAP
    def handle_offline_packet(packet):
        if not packet.haslayer(IP):
            return
            
        if packet.haslayer(TCP): proto = "TCP"
        elif packet.haslayer(UDP): proto = "UDP"
        else: return

        ip = packet[IP]
        layer = packet[proto]
        
        # Odtwarzamy kierunek ruchu i flow_id
        direction = "out" if ip.src in local_ips else "in"
        flow_id = get_flow_id(ip.src, ip.dst, layer.sport, layer.dport, proto)

        # Wyciągamy cechy
        features = extractor.extract_features(
            app=app_label, 
            direction=direction, 
            protocol=proto, 
            packet=packet, 
            flow_id=flow_id
        )

        # Zapisujemy wiersz do CSV
        extractor.save_to_csv(features)

    # Główna magia: Scapy czyta plik PCAP (offline="...") zamiast słuchać interfejsu (iface="...")
    sniff(offline=pcap_path, prn=handle_offline_packet, store=False)
    
    extractor.close_all()
    print("[+] Zakończono ekstrakcję. Dane zapisano do CSV.")

if __name__ == "__main__":
    # Twoje IP maszyny z momentu nagrywania PCAPa (ważne, by poprawnie określić kierunek in/out)
    MY_OLD_LOCAL_IPS = {"192.168.1.100"} 
    
    # Przykładowe wywołanie
    process_pcap_offline(
        pcap_path="traffic_logs/spotify_2023-10-25.pcap", 
        app_label="spotify", 
        local_ips=MY_OLD_LOCAL_IPS
    )

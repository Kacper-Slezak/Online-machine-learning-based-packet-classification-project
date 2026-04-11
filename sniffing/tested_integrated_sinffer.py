from scapy.all import sniff, PcapWriter
from scapy.layers.inet import IP, TCP, UDP
import psutil
import threading
import time
import os
import socket
from datetime import datetime


TARGET_APP = "spotify"  # Part of process name to filter (case-insensitive)
DIR_FOR_SAVING = "traffic_logs"
BPF_FILTER = "tcp or udp"  # Capture only TCP and UDP packets

if not os.path.exists(DIR_FOR_SAVING):
    os.makedirs(DIR_FOR_SAVING)

def get_local_ip():
    """Function to get the local IP address of the machine."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

class AppSniffer:
    def __init__(self):
        self.today_date = None
        self.writer = None
        self.packet_count = 0
        self.local_ip = get_local_ip()
        
        self.active_ports_map = {}
        
    def update_ports_daemon(self):
        """Thread for updating the port map."""
        while True:
            temp_map = {}
            try:
                connections = psutil.net_connections(kind='inet')
                for conn in connections:
                    if conn.status == 'ESTABLISHED' and conn.pid:
                        try:
                            proc = psutil.Process(conn.pid)
                            temp_map[conn.laddr.port] = proc.name().lower()
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue
                self.active_ports_map = temp_map
            except psutil.AccessDenied:
                pass
            time.sleep(1) 

    def get_file_name(self):
        """Function to generate file name based on current date and target app."""
        date_str = datetime.now().strftime("%Y-%m-%d")
        if self.today_date != date_str:
            if self.writer:
                self.writer.close()
            self.today_date = date_str
            file_name = f"{DIR_FOR_SAVING}/{TARGET_APP}_traffic_{date_str}.pcap"
            self.writer = PcapWriter(file_name, append=True, sync=True)
            print(f"[*] Plik zapisu: {file_name}")

    def packet_handler(self, packet):
        """Function called for each captured packet."""
        if packet.haslayer(IP) and (packet.haslayer(TCP) or packet.haslayer(UDP)):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            if packet.haslayer(TCP):
                sport, dport = packet[TCP].sport, packet[TCP].dport
            else:
                sport, dport = packet[UDP].sport, packet[UDP].dport

            local_port = None
            if src_ip == self.local_ip:
                local_port = sport  
            elif dst_ip == self.local_ip:
                local_port = dport 


            if local_port and local_port in self.active_ports_map:
                app_name = self.active_ports_map[local_port]
                
                if TARGET_APP in app_name:
                    self.get_file_name()
                    self.writer.write(packet)
                    self.packet_count += 1
                    
                    direction = "OUT ->" if src_ip == self.local_ip else "IN  <-"
                    print(f"[+] Captured {TARGET_APP} | {direction} | Size: {len(packet)}B", end="\r")

    def start(self):
        print(f"[*] Address of this machine: {self.local_ip}")
        print(f"[*] Target app: '{TARGET_APP}'")
        
        port_thread = threading.Thread(target=self.update_ports_daemon, daemon=True)
        port_thread.start()
        
        time.sleep(2)
        
        print("[*] Sniffer started. Press Ctrl+C to stop.")
        sniff(filter=BPF_FILTER, prn=self.packet_handler, store=False)

if __name__ == "__main__":
    sniffer = AppSniffer()
    try:
        sniffer.start()
    except KeyboardInterrupt:
        print(f"\n[*] Stopped. Saved {sniffer.packet_count} packets from the {TARGET_APP} stream.")
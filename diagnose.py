"""
diagnose.py — Uruchom to PRZED snifferem żeby zobaczyć co psutil widzi.
Nie wymaga root na Windows, wymaga na Linux/Mac.
"""
import psutil
import socket

def diagnose():
    print("=" * 60)
    print("1. PROCESY z 'spotify' w nazwie:")
    print("=" * 60)
    found_procs = []
    for proc in psutil.process_iter(['pid', 'name', 'status']):
        try:
            if 'spotify' in proc.info['name'].lower():
                found_procs.append(proc)
                print(f"  PID={proc.info['pid']}  NAME={proc.info['name']}  STATUS={proc.info['status']}")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    if not found_procs:
        print("  [!] NIE ZNALEZIONO żadnego procesu Spotify!")
        print("      Upewnij się że Spotify jest uruchomione.")

    print()
    print("=" * 60)
    print("2. WSZYSTKIE połączenia sieciowe (TCP + UDP):")
    print("=" * 60)
    
    try:
        connections = psutil.net_connections(kind='inet')
    except psutil.AccessDenied:
        print("  [!] BRAK UPRAWNIEŃ — uruchom jako Administrator/sudo")
        return

    spotify_pids = {p.info['pid'] for p in found_procs}
    
    print(f"\n  Połączenia należące do Spotify (PID: {spotify_pids}):")
    spotify_conns = 0
    for conn in connections:
        if conn.pid in spotify_pids:
            laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "—"
            raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "—"
            print(f"  [{conn.type.name}] {laddr} → {raddr}  STATUS={conn.status}  PID={conn.pid}")
            spotify_conns += 1

    if spotify_conns == 0:
        print("  [!] Spotify nie ma żadnych aktywnych połączeń!")
        print("      Spróbuj odtworzyć coś w Spotify i uruchom skrypt ponownie.")

    print(f"\n  Wszystkie połączenia (pierwsze 20):")
    for conn in connections[:20]:
        try:
            name = psutil.Process(conn.pid).name() if conn.pid else "?"
        except Exception:
            name = "?"
        laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "—"
        raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "—"
        print(f"  [{conn.type.name}] {laddr} → {raddr}  STATUS={conn.status}  APP={name}")

    print()
    print("=" * 60)
    print("3. LOKALNY ADRES IP maszyny:")
    print("=" * 60)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        local_ip = s.getsockname()[0]
    except Exception:
        local_ip = '127.0.0.1'
    finally:
        s.close()
    print(f"  Wykryty IP: {local_ip}")
    print()
    print("  Wszystkie interfejsy sieciowe:")
    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET:
                print(f"    {iface}: {addr.address}")

if __name__ == "__main__":
    diagnose()
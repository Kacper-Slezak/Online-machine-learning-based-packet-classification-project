import psutil
import time

def get_port_to_app_map():
    """
    Skanuje system operacyjny i zwraca słownik:
    Klucz: Port lokalny (int)
    Wartość: Nazwa procesu/aplikacji (string)
    """
    port_map = {}
    
    # Pobieramy wszystkie aktywne połączenia sieciowe (IPv4 i IPv6)
    try:
        connections = psutil.net_connections(kind='inet')
    except psutil.AccessDenied:
        print("Brak uprawnień Administratora/Root. Niektóre procesy będą niewidoczne.")
        return {}

    for conn in connections:
        # Interesują nas tylko połączenia nawiązane (ESTABLISHED) z przypisanym PID
        if conn.status == 'ESTABLISHED' and conn.pid:
            try:
                # Pobierz obiekt procesu na podstawie jego numeru PID
                process = psutil.Process(conn.pid)
                app_name = process.name()
                
                # Pobierz lokalny port tego połączenia
                local_port = conn.laddr.port
                
                # Zapisz w słowniku
                port_map[local_port] = app_name
                
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                # Proces mógł zostać zamknięty ułamek sekundy temu lub nie mamy do niego dostępu
                continue
                
    return port_map

def monitor_active_apps():
    """Funkcja do testowania i podglądu działania mapowania na żywo."""
    print(f"{'PORT LOKALNY':<15} | {'APLIKACJA':<30}")
    print("-" * 50)
    
    try:
        while True:
            current_map = get_port_to_app_map()
            
            # Czyścimy ekran (opcjonalnie, żeby ładnie wyglądało w konsoli)
            # import os; os.system('cls' if os.name == 'nt' else 'clear')
            
            # Wypisujemy tylko unikalne aplikacje i ich porty z danej sekundy
            for port, app in current_map.items():
                # Możesz tu odfiltrować śmieci, np. if "chrome" in app.lower():
                print(f"{port:<15} | {app:<30}")
                
            print("\n[*] Odświeżam za 2 sekundy... (Ctrl+C aby wyjść)\n")
            time.sleep(2)
            
    except KeyboardInterrupt:
        print("\n[*] Zakończono monitorowanie.")

if __name__ == "__main__":
    monitor_active_apps()
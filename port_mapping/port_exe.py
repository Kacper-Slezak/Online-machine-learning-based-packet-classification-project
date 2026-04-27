import psutil
import time

def get_port_to_app_map():
    """
    Scans the operating system and returns a dictionary:
    Key: Local port (int)
    Value: Process/Application name (string)
    """
    port_map = {}
    
    # Get all active network connections (IPv4 and IPv6)
    try:
        connections = psutil.net_connections(kind='inet')
    except psutil.AccessDenied:
        print("Administrator/Root privileges missing. Some processes will be invisible.")
        return {}

    for conn in connections:
        # We are only interested in ESTABLISHED connections with an assigned PID
        if conn.status == 'ESTABLISHED' and conn.pid:
            try:
                # Get the process object based on its PID
                process = psutil.Process(conn.pid)
                app_name = process.name()
                
                # Get the local port of this connection
                local_port = conn.laddr.port
                
                # Save to dictionary
                port_map[local_port] = app_name
                
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                # The process might have been closed a fraction of a second ago or we lack access
                continue
                
    return port_map

def monitor_active_apps():
    """Function for testing and live preview of the mapping."""
    print(f"{'LOCAL PORT':<15} | {'APPLICATION':<30}")
    print("-" * 50)
    
    try:
        while True:
            current_map = get_port_to_app_map()
            
            # Clear the screen (optional, for a cleaner console view)
            # import os; os.system('cls' if os.name == 'nt' else 'clear')
            
            # Print only unique applications and their ports from the current second
            for port, app in current_map.items():
                # You can filter out noise here, e.g., if "chrome" in app.lower():
                print(f"{port:<15} | {app:<30}")
                
            print("\n[*] Refreshing in 2 seconds... (Press Ctrl+C to exit)\n")
            time.sleep(2)
            
    except KeyboardInterrupt:
        print("\n[*] Monitoring finished.")

if __name__ == "__main__":
    monitor_active_apps()
import socket
import threading
from queue import Queue

# Configuration 
target = "localhost"  # Target IP address
port_range = (1, 1024)  # The range of ports to scan

# Vulnerabilities for banner matching
known_vulnerabilities = {
    "FTP": ["vsftpd 2.3.4", "ProFTPD 1.3.3c"],
    "SSH": ["OpenSSH 6.6.1p1 Ubuntu-2ubuntu2"],
    "HTTP": ["Apache 2.2.22", "Apache 2.4.49"]
}

# Check for known vulnerabilities in service banners
def check_vulnerabilities(banner):
    for service, vulnerable_versions in known_vulnerabilities.items():
        for version in vulnerable_versions:
            if version in banner:
                print(f"[!] Vulnerability detected: {banner}")
                return True
    return False

# Grab banners from open ports
def grab_banner(port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.connect((target, port))
        banner = sock.recv(1024).decode().strip()
        print(f"    Banner on port {port}: {banner}")
        if check_vulnerabilities(banner):
            print(f"[!] Known vulnerability detected on port {port}: {banner}")
        sock.close()
        return banner
    except:
        return None

# Scan a specific port
def scan_port(port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        if result == 0:
            print(f"[+] Port {port} is open")
            banner = grab_banner(port)
            if banner:
                print(f"    Banner: {banner}")
        sock.close()
    except:
        pass

# Thread function for multi-threaded scanning
def threader():
    while True:
        port = queue.get()
        scan_port(port)
        queue.task_done()

# Set up multi-threading
queue = Queue()
num_threads = 100

# Starting threads
for _ in range(num_threads):
    thread = threading.Thread(target=threader)
    thread.daemon = True
    thread.start()

# Adding ports to the queue
for port in range(port_range[0], port_range[1] + 1):
    queue.put(port)

queue.join()

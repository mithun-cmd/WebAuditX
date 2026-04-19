import socket
import threading
from urllib.parse import urlparse


# -------------------------------
# 🔹 FAST MODE (Default)
# -------------------------------
FAST_PORTS = [
    21, 22, 23, 25, 53,
    80, 110, 139, 143,
    443, 445, 8080, 8443,
    3306, 3389, 5900, 6379,
    8000
]

# -------------------------------
# 🔹 FULL MODE (Optional)
# -------------------------------
FULL_PORTS = FAST_PORTS + [
    81, 82, 83, 84, 85,
    88, 389, 636, 1433,
    1521, 2049, 2082, 2083,
    2181, 2483, 2484, 3000,
    4444, 5000, 5060, 5432,
    5601, 5985, 5986, 7001,
    7002, 8008, 8010, 8081,
    8082, 8088, 8090, 8444,
    8888, 9000, 9090, 9200,
    27017
]

# -------------------------------
# 🔹 Port → Service Mapping
# -------------------------------
PORT_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP",
    5900: "VNC", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    8000: "Dev Server", 5000: "Flask",
    3000: "NodeJS", 27017: "MongoDB"
}


def get_service(port):
    return PORT_SERVICES.get(port, "Unknown")


# -------------------------------
# 🔹 MAIN SCAN FUNCTION
# -------------------------------
def scan_ports(url, logger=None, mode="fast"):

    # ✅ Extract hostname
    parsed = urlparse(url)
    host = parsed.hostname

    if not host:
        return []

    # ✅ Choose mode
    if mode == "full":
        ports = FULL_PORTS
    else:
        ports = FAST_PORTS

    # ✅ Smart: include port from URL
    if parsed.port and parsed.port not in ports:
        ports.append(parsed.port)

    open_ports = []
    lock = threading.Lock()

    if logger:
        logger(f"[+] Starting port scan ({mode.upper()} mode)...")
    else:
        print("\n[+] Scanning Ports...\n")

    # -------------------------------
    # 🔹 Worker Function
    # -------------------------------
    def scan_single_port(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)  # ⚡ faster scanning

            result = sock.connect_ex((host, port))

            if result == 0:
                service = PORT_SERVICES.get(port, "Unknown")

                with lock:
                    open_ports.append((port, service))

                if logger:
                    logger(f"[!] Port {port} ({service}) is OPEN")
                else:
                    print(f"[+] Port {port} ({service}) is OPEN")

            sock.close()

        except:
            pass

    # -------------------------------
    # 🔹 Multithreading
    # -------------------------------
    threads = []

    for port in ports:
        t = threading.Thread(target=scan_single_port, args=(port,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    if logger and not open_ports:
        logger("[+] No open ports detected")

    # Return only port numbers (for compatibility)
    return [p[0] for p in sorted(open_ports)]
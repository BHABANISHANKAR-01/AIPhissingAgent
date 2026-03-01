"""
Port Scanner Module — TCP connect scan with banner grabbing.
"""
import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from backend.config import SCAN_TIMEOUT, MAX_THREADS, SERVICE_PORTS, TOP_1000_PORTS


class PortScanner:
    """TCP port scanner with service detection."""

    def __init__(self, target, ports=None, timeout=SCAN_TIMEOUT, callback=None):
        self.target = target
        self.timeout = timeout
        self.callback = callback  # Called with (port, status, service, banner)
        self.results = []
        self.lock = threading.Lock()

        if ports == "top1000":
            self.ports = TOP_1000_PORTS
        elif ports == "all":
            self.ports = list(range(1, 65536))
        elif ports:
            self.ports = ports
        else:
            self.ports = TOP_1000_PORTS[:100]

    def _log(self, msg):
        if self.callback:
            self.callback(msg)

    def scan_port(self, port):
        """Scan a single port via TCP connect."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))

            if result == 0:
                service = SERVICE_PORTS.get(port, "unknown")
                banner = self._grab_banner(sock, port)
                entry = {
                    "port": port,
                    "state": "open",
                    "service": service,
                    "banner": banner
                }
                with self.lock:
                    self.results.append(entry)
                self._log(f"[OPEN] Port {port}/{service} — {banner or 'no banner'}")
                sock.close()
                return entry
            sock.close()
        except socket.timeout:
            pass
        except Exception:
            pass
        return None

    def _grab_banner(self, sock, port):
        """Attempt to grab service banner."""
        try:
            if port in (80, 443, 8080, 8443):
                sock.sendall(b"HEAD / HTTP/1.1\r\nHost: " + self.target.encode() + b"\r\n\r\n")
            elif port == 22:
                pass  # SSH sends banner automatically
            elif port in (21, 25, 110, 143):
                pass  # These protocols send banners automatically
            else:
                sock.sendall(b"\r\n")

            sock.settimeout(2)
            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            return banner[:200] if banner else ""
        except Exception:
            return ""

    def run(self):
        """Execute the port scan across all configured ports."""
        self._log(f"Starting port scan on {self.target} ({len(self.ports)} ports)")
        self.results = []

        with ThreadPoolExecutor(max_workers=min(MAX_THREADS, len(self.ports))) as executor:
            futures = {executor.submit(self.scan_port, p): p for p in self.ports}
            done = 0
            total = len(futures)
            for future in as_completed(futures):
                done += 1
                if done % 100 == 0 or done == total:
                    self._log(f"Progress: {done}/{total} ports scanned ({len(self.results)} open)")

        self.results.sort(key=lambda x: x["port"])
        self._log(f"Port scan complete: {len(self.results)} open ports found")
        return self.results

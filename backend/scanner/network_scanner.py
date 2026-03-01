"""
Network Scanner Module — Host discovery and OS fingerprinting.
"""
import socket
import subprocess
import platform
import re
from concurrent.futures import ThreadPoolExecutor, as_completed


class NetworkScanner:
    """Network discovery and basic OS fingerprinting."""

    def __init__(self, target, callback=None):
        self.target = target
        self.callback = callback
        self.results = {}

    def _log(self, msg):
        if self.callback:
            self.callback(msg)

    def resolve_host(self):
        """Resolve hostname to IP address."""
        try:
            ip = socket.gethostbyname(self.target)
            self._log(f"Resolved {self.target} → {ip}")
            self.results["ip"] = ip
            self.results["hostname"] = self.target

            # Reverse DNS
            try:
                reverse = socket.gethostbyaddr(ip)
                self.results["reverse_dns"] = reverse[0]
                self._log(f"Reverse DNS: {reverse[0]}")
            except Exception:
                self.results["reverse_dns"] = ""

            return ip
        except socket.gaierror as e:
            self._log(f"[ERROR] Could not resolve {self.target}: {e}")
            self.results["error"] = str(e)
            return None

    def ping_host(self, host=None):
        """Check if host is alive via ICMP ping."""
        target = host or self.target
        self._log(f"Pinging {target}...")

        param = "-n" if platform.system().lower() == "windows" else "-c"
        try:
            output = subprocess.run(
                ["ping", param, "3", target],
                capture_output=True, text=True, timeout=10
            )
            alive = output.returncode == 0

            # Parse TTL for OS fingerprinting
            ttl = None
            ttl_match = re.search(r"TTL[=:](\d+)", output.stdout, re.IGNORECASE)
            if ttl_match:
                ttl = int(ttl_match.group(1))

            # Parse latency
            latency = None
            lat_match = re.search(r"(?:time[=<])(\d+\.?\d*)", output.stdout, re.IGNORECASE)
            if lat_match:
                latency = float(lat_match.group(1))

            self.results["alive"] = alive
            self.results["ttl"] = ttl
            self.results["latency_ms"] = latency

            if alive:
                os_guess = self._guess_os(ttl)
                self.results["os_guess"] = os_guess
                self._log(f"Host is UP (TTL={ttl}, latency={latency}ms, OS≈{os_guess})")
            else:
                self._log(f"Host appears DOWN or blocks ICMP")

            return alive
        except subprocess.TimeoutExpired:
            self._log(f"Ping timed out for {target}")
            self.results["alive"] = False
            return False
        except FileNotFoundError:
            self._log(f"[WARN] ping command not found, skipping ICMP check")
            self.results["alive"] = None
            return None

    def _guess_os(self, ttl):
        """Guess OS based on TTL value."""
        if ttl is None:
            return "Unknown"
        if ttl <= 64:
            return "Linux/Unix"
        elif ttl <= 128:
            return "Windows"
        elif ttl <= 255:
            return "Network Device (Cisco/Solaris)"
        return "Unknown"

    def scan_subnet(self, cidr=None):
        """Discover live hosts on the local subnet (if target is in a /24)."""
        ip = self.results.get("ip") or self.resolve_host()
        if not ip:
            return []

        # Only scan /24 subnet
        parts = ip.split(".")
        if len(parts) != 4:
            return []

        base = ".".join(parts[:3])
        self._log(f"Scanning subnet {base}.0/24 for live hosts...")

        live_hosts = []

        def check_host(host_ip):
            try:
                param = "-n" if platform.system().lower() == "windows" else "-c"
                result = subprocess.run(
                    ["ping", param, "1", "-w", "1000", host_ip],
                    capture_output=True, text=True, timeout=3
                )
                if result.returncode == 0:
                    return host_ip
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=30) as executor:
            futures = {executor.submit(check_host, f"{base}.{i}"): i for i in range(1, 255)}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    live_hosts.append(result)
                    self._log(f"  Host UP: {result}")

        self.results["subnet_hosts"] = live_hosts
        self._log(f"Found {len(live_hosts)} live hosts on {base}.0/24")
        return live_hosts

    def run(self):
        """Execute full network scan."""
        self._log(f"Starting network scan for {self.target}")
        self.resolve_host()
        self.ping_host()
        self._log("Network scan complete")
        return self.results

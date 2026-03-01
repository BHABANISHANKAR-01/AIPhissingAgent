"""
Vulnerability Analyzer — Correlate services to known CVEs and score findings.
"""
import re


# ─── Known Vulnerable Service Versions (educational database) ──────────
KNOWN_VULNS = {
    "openssh": [
        {"versions": ["7.0", "7.1", "7.2", "7.3", "7.4"],
         "cve": "CVE-2016-10009", "cvss": 7.3,
         "title": "OpenSSH Agent Forwarding RCE",
         "description": "An attacker with access to an SSH agent can execute commands.",
         "remediation": "Upgrade to OpenSSH 7.5 or later."},
        {"versions": ["6.0", "6.1", "6.2", "6.3", "6.4", "6.5", "6.6"],
         "cve": "CVE-2014-1692", "cvss": 7.5,
         "title": "OpenSSH Denial of Service",
         "description": "Memory corruption vulnerability allows remote DoS.",
         "remediation": "Upgrade to OpenSSH 6.7 or later."},
    ],
    "apache": [
        {"versions": ["2.4.49"],
         "cve": "CVE-2021-41773", "cvss": 9.8,
         "title": "Apache Path Traversal & RCE",
         "description": "Path traversal and remote code execution in Apache HTTP Server 2.4.49.",
         "remediation": "Upgrade to Apache 2.4.51 or later."},
        {"versions": ["2.4.50"],
         "cve": "CVE-2021-42013", "cvss": 9.8,
         "title": "Apache Path Traversal (Bypass)",
         "description": "Incomplete fix for CVE-2021-41773 in Apache 2.4.50.",
         "remediation": "Upgrade to Apache 2.4.51 or later."},
    ],
    "nginx": [
        {"versions": ["1.16", "1.17", "1.18"],
         "cve": "CVE-2021-23017", "cvss": 7.7,
         "title": "nginx DNS Resolver Vulnerability",
         "description": "1-byte memory overwrite in resolver can lead to crash or RCE.",
         "remediation": "Upgrade to nginx 1.20.1 or later."},
    ],
    "mysql": [
        {"versions": ["5.7"],
         "cve": "CVE-2020-14812", "cvss": 4.9,
         "title": "MySQL Server Optimizer Vulnerability",
         "description": "Easily exploitable vulnerability allows high privileged attacker to DoS.",
         "remediation": "Upgrade MySQL to the latest patch version."},
    ],
    "microsoft-iis": [
        {"versions": ["10.0"],
         "cve": "CVE-2021-31166", "cvss": 9.8,
         "title": "IIS HTTP Protocol Stack RCE",
         "description": "Wormable vulnerability in HTTP.sys allows unauthenticated RCE.",
         "remediation": "Apply Microsoft security patch KB5003171."},
    ],
    "vsftpd": [
        {"versions": ["2.3.4"],
         "cve": "CVE-2011-2523", "cvss": 10.0,
         "title": "vsftpd 2.3.4 Backdoor",
         "description": "Compromised vsftpd 2.3.4 contains a backdoor command execution vulnerability.",
         "remediation": "Upgrade to vsftpd 3.0 or later from a trusted source."},
    ],
    "proftpd": [
        {"versions": ["1.3.5"],
         "cve": "CVE-2015-3306", "cvss": 10.0,
         "title": "ProFTPD mod_copy RCE",
         "description": "mod_copy allows unauthenticated file copy leading to remote code execution.",
         "remediation": "Upgrade to ProFTPD 1.3.6 or later."},
    ],
}


class VulnAnalyzer:
    """Correlate scan results with known vulnerabilities."""

    def __init__(self, callback=None):
        self.callback = callback
        self.findings = []

    def _log(self, msg):
        if self.callback:
            self.callback(msg)

    def analyze_banners(self, port_results):
        """Analyze service banners for known vulnerable versions."""
        self._log("Analyzing service banners for known vulnerabilities...")

        for entry in port_results:
            banner = entry.get("banner", "").lower()
            service = entry.get("service", "").lower()
            port = entry.get("port", 0)

            if not banner:
                continue

            for product, vulns in KNOWN_VULNS.items():
                if product in banner or product in service:
                    for vuln in vulns:
                        for ver in vuln["versions"]:
                            if ver in banner:
                                finding = {
                                    "severity": self._cvss_to_severity(vuln["cvss"]),
                                    "category": "known_cve",
                                    "title": vuln["title"],
                                    "description": vuln["description"],
                                    "evidence": f"Port {port}: {banner}",
                                    "remediation": vuln["remediation"],
                                    "cvss_score": vuln["cvss"],
                                    "cve_id": vuln["cve"],
                                    "port": port,
                                    "service": entry.get("service", "")
                                }
                                self.findings.append(finding)
                                self._log(f"  [CVE] {vuln['cve']} on port {port}: {vuln['title']} (CVSS {vuln['cvss']})")
                                break

    def analyze_open_ports(self, port_results):
        """Flag commonly exploitable open ports."""
        self._log("Analyzing open ports for security risks...")

        risky_ports = {
            21: ("FTP", "medium", "FTP often allows anonymous access and transmits credentials in plaintext."),
            23: ("Telnet", "high", "Telnet transmits all data including credentials in plaintext."),
            25: ("SMTP", "low", "Open SMTP relay can be used for spam."),
            135: ("MSRPC", "medium", "MS-RPC can expose internal services."),
            139: ("NetBIOS", "medium", "NetBIOS can expose shared files and system information."),
            445: ("SMB", "high", "SMB has been targeted by major exploits like EternalBlue."),
            1433: ("MSSQL", "high", "Database exposed to the network."),
            3306: ("MySQL", "high", "Database exposed to the network."),
            3389: ("RDP", "high", "Remote Desktop exposed — vulnerable to brute force and BlueKeep."),
            5432: ("PostgreSQL", "high", "Database exposed to the network."),
            5900: ("VNC", "high", "VNC often has weak authentication."),
            6379: ("Redis", "critical", "Redis often runs without authentication."),
            27017: ("MongoDB", "critical", "MongoDB often runs without authentication."),
        }

        for entry in port_results:
            port = entry["port"]
            if port in risky_ports:
                name, severity, desc = risky_ports[port]
                finding = {
                    "severity": severity,
                    "category": "risky_service",
                    "title": f"Potentially Risky Service: {name} (port {port})",
                    "description": desc,
                    "evidence": f"Port {port} is open: {entry.get('banner', 'no banner')[:100]}",
                    "remediation": f"Consider restricting access to port {port} via firewall rules.",
                    "cvss_score": {"critical": 9.0, "high": 7.0, "medium": 5.0, "low": 3.0, "info": 0.0}[severity],
                    "port": port,
                    "service": name
                }
                self.findings.append(finding)
                self._log(f"  [{severity.upper()}] {name} on port {port}")

    def _cvss_to_severity(self, score):
        if score >= 9.0:
            return "critical"
        elif score >= 7.0:
            return "high"
        elif score >= 4.0:
            return "medium"
        elif score >= 0.1:
            return "low"
        return "info"

    def run(self, port_results):
        """Run full vulnerability analysis on scan results."""
        self._log("Starting vulnerability analysis...")
        self.findings = []
        self.analyze_banners(port_results)
        self.analyze_open_ports(port_results)
        self._log(f"Vulnerability analysis complete: {len(self.findings)} issues found")
        return self.findings

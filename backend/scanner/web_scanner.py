"""
Web Application Scanner — HTTP security headers, directory enum, basic vuln checks.
"""
import requests
import ssl
import socket
import re
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

# Suppress insecure warnings for testing
requests.packages.urllib3.disable_warnings()


class WebScanner:
    """Web application vulnerability scanner for educational use."""

    SECURITY_HEADERS = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "X-XSS-Protection",
        "Referrer-Policy",
        "Permissions-Policy",
        "Cross-Origin-Embedder-Policy",
        "Cross-Origin-Opener-Policy",
        "Cross-Origin-Resource-Policy",
    ]

    COMMON_PATHS = [
        "/robots.txt", "/sitemap.xml", "/.env", "/.git/config",
        "/wp-admin/", "/wp-login.php", "/admin/", "/administrator/",
        "/login", "/api/", "/swagger/", "/graphql",
        "/.htaccess", "/server-status", "/server-info",
        "/phpinfo.php", "/info.php", "/test.php",
        "/backup/", "/backups/", "/db/", "/database/",
        "/.svn/entries", "/.DS_Store", "/web.config",
        "/crossdomain.xml", "/clientaccesspolicy.xml",
        "/actuator/health", "/actuator/env",
    ]

    # Safe, educational XSS test payloads (will not cause harm)
    XSS_PAYLOADS = [
        '<script>alert("XSS")</script>',
        '"><img src=x onerror=alert(1)>',
        "javascript:alert(1)",
        "<svg/onload=alert(1)>",
    ]

    # Safe SQLi test payloads
    SQLI_PAYLOADS = [
        "' OR '1'='1",
        "1; DROP TABLE users--",
        "' UNION SELECT NULL--",
        "1' AND '1'='1",
    ]

    SQLI_INDICATORS = [
        "sql syntax", "mysql", "sqlite", "postgresql", "oracle",
        "microsoft sql", "unclosed quotation", "syntax error",
        "unterminated string", "you have an error in your sql",
        "warning: mysql", "pg_query", "sqlstate",
    ]

    def __init__(self, target, callback=None):
        self.target = self._normalize_url(target)
        self.callback = callback
        self.results = {
            "headers": {},
            "missing_headers": [],
            "technologies": [],
            "directories": [],
            "vulnerabilities": [],
            "ssl_info": {},
            "server_info": {}
        }
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "AIPhishingAgent-PenTest/1.0 (Educational)"
        })
        self.session.verify = False

    def _normalize_url(self, target):
        if not target.startswith(("http://", "https://")):
            target = "http://" + target
        return target.rstrip("/")

    def _log(self, msg):
        if self.callback:
            self.callback(msg)

    def check_headers(self):
        """Analyze HTTP security headers."""
        self._log("Checking HTTP security headers...")
        try:
            resp = self.session.get(self.target, timeout=10, allow_redirects=True)
            self.results["headers"] = dict(resp.headers)
            self.results["status_code"] = resp.status_code

            # Server info
            server = resp.headers.get("Server", "")
            powered_by = resp.headers.get("X-Powered-By", "")
            if server:
                self.results["server_info"]["server"] = server
                self._log(f"  Server: {server}")
            if powered_by:
                self.results["server_info"]["powered_by"] = powered_by
                self._log(f"  Powered-By: {powered_by}")
                self.results["vulnerabilities"].append({
                    "type": "info_disclosure",
                    "severity": "low",
                    "title": "X-Powered-By Header Exposed",
                    "description": f"Server reveals technology stack: {powered_by}",
                    "remediation": "Remove X-Powered-By header to reduce information disclosure."
                })

            # Check missing security headers
            for header in self.SECURITY_HEADERS:
                if header.lower() not in {k.lower(): v for k, v in resp.headers.items()}:
                    self.results["missing_headers"].append(header)
                    severity = "medium" if header in (
                        "Strict-Transport-Security", "Content-Security-Policy"
                    ) else "low"
                    self.results["vulnerabilities"].append({
                        "type": "missing_header",
                        "severity": severity,
                        "title": f"Missing Security Header: {header}",
                        "description": f"The {header} header is not set.",
                        "remediation": f"Configure the {header} header on the web server."
                    })

            self._log(f"  Missing headers: {len(self.results['missing_headers'])}")
            return self.results["headers"]
        except requests.RequestException as e:
            self._log(f"  [ERROR] Could not fetch headers: {e}")
            return {}

    def detect_technologies(self):
        """Fingerprint web technologies from response headers and content."""
        self._log("Detecting web technologies...")
        try:
            resp = self.session.get(self.target, timeout=10)
            body = resp.text.lower()
            headers_str = str(resp.headers).lower()

            tech_patterns = {
                "WordPress": ["wp-content", "wp-includes", "wordpress"],
                "Joomla": ["joomla", "/components/com_"],
                "Drupal": ["drupal", "sites/default/files"],
                "React": ["react", "__react", "react-dom"],
                "Angular": ["ng-app", "angular", "ng-controller"],
                "Vue.js": ["vue.js", "v-bind", "v-model"],
                "jQuery": ["jquery"],
                "Bootstrap": ["bootstrap"],
                "nginx": ["nginx"],
                "Apache": ["apache"],
                "IIS": ["microsoft-iis"],
                "PHP": ["x-powered-by: php", ".php"],
                "ASP.NET": ["asp.net", "__viewstate"],
                "Node.js": ["x-powered-by: express", "node.js"],
                "Django": ["csrfmiddlewaretoken", "django"],
                "Flask": ["werkzeug"],
                "Laravel": ["laravel"],
                "Spring": ["x-application-context"],
            }

            for tech, patterns in tech_patterns.items():
                for pattern in patterns:
                    if pattern in body or pattern in headers_str:
                        if tech not in self.results["technologies"]:
                            self.results["technologies"].append(tech)
                            self._log(f"  Detected: {tech}")
                        break

        except requests.RequestException as e:
            self._log(f"  [ERROR] Tech detection failed: {e}")

    def enumerate_directories(self):
        """Check for common sensitive directories and files."""
        self._log("Enumerating directories and files...")
        found = []

        def check_path(path):
            url = urljoin(self.target + "/", path.lstrip("/"))
            try:
                resp = self.session.get(url, timeout=5, allow_redirects=False)
                if resp.status_code in (200, 301, 302, 403):
                    return {
                        "path": path,
                        "url": url,
                        "status": resp.status_code,
                        "size": len(resp.content)
                    }
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(check_path, p): p for p in self.COMMON_PATHS}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found.append(result)
                    status = result["status"]
                    path = result["path"]
                    self._log(f"  [{status}] {path}")

                    # Flag sensitive findings
                    if any(s in path for s in [".env", ".git", ".svn", "backup", "phpinfo", "actuator"]):
                        self.results["vulnerabilities"].append({
                            "type": "sensitive_file",
                            "severity": "high" if ".env" in path or ".git" in path else "medium",
                            "title": f"Sensitive File/Directory Found: {path}",
                            "description": f"Accessible at {result['url']} (HTTP {status})",
                            "remediation": f"Restrict access to {path} via web server configuration."
                        })

        self.results["directories"] = found
        self._log(f"  Found {len(found)} accessible paths")
        return found

    def check_ssl(self):
        """Analyze SSL/TLS certificate."""
        parsed = urlparse(self.target)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        if parsed.scheme != "https":
            # Try HTTPS anyway
            try:
                self.session.get(f"https://{host}", timeout=5)
            except Exception:
                self._log("  Target does not support HTTPS")
                self.results["ssl_info"]["https_supported"] = False
                self.results["vulnerabilities"].append({
                    "type": "no_ssl",
                    "severity": "medium",
                    "title": "HTTPS Not Supported",
                    "description": "The target does not appear to support HTTPS.",
                    "remediation": "Enable HTTPS with a valid TLS certificate."
                })
                return

        self._log("Checking SSL/TLS certificate...")
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
                s.settimeout(5)
                s.connect((host, port))
                cert = s.getpeercert()

            self.results["ssl_info"] = {
                "https_supported": True,
                "subject": dict(x[0] for x in cert.get("subject", [])),
                "issuer": dict(x[0] for x in cert.get("issuer", [])),
                "version": cert.get("version"),
                "not_before": cert.get("notBefore"),
                "not_after": cert.get("notAfter"),
                "serial": cert.get("serialNumber"),
            }
            self._log(f"  Cert issued to: {self.results['ssl_info']['subject']}")
            self._log(f"  Cert expires: {cert.get('notAfter')}")
        except ssl.SSLCertVerificationError as e:
            self.results["ssl_info"]["error"] = str(e)
            self.results["vulnerabilities"].append({
                "type": "ssl_error",
                "severity": "high",
                "title": "SSL Certificate Verification Failed",
                "description": str(e),
                "remediation": "Install a valid SSL certificate from a trusted CA."
            })
            self._log(f"  [WARN] SSL error: {e}")
        except Exception as e:
            self._log(f"  [ERROR] SSL check failed: {e}")

    def check_xss(self):
        """Test for reflected XSS (educational, safe payloads)."""
        self._log("Testing for reflected XSS vulnerabilities...")
        try:
            # Get the page and find form inputs / URL params
            resp = self.session.get(self.target, timeout=10)

            # Test via URL parameters
            for payload in self.XSS_PAYLOADS:
                test_url = f"{self.target}/?q={payload}&search={payload}"
                try:
                    r = self.session.get(test_url, timeout=5)
                    if payload in r.text:
                        self.results["vulnerabilities"].append({
                            "type": "xss",
                            "severity": "high",
                            "title": "Potential Reflected XSS",
                            "description": f"Payload reflected in response: {payload[:50]}",
                            "evidence": f"URL: {test_url}",
                            "remediation": "Implement proper input sanitization and output encoding."
                        })
                        self._log(f"  [VULN] Reflected XSS found with payload: {payload[:30]}")
                        break
                except Exception:
                    continue

        except Exception as e:
            self._log(f"  [ERROR] XSS check failed: {e}")

    def check_sqli(self):
        """Test for SQL injection indicators (educational, safe payloads)."""
        self._log("Testing for SQL injection indicators...")
        try:
            # Get baseline response
            baseline = self.session.get(self.target, timeout=10)
            baseline_len = len(baseline.text)

            for payload in self.SQLI_PAYLOADS:
                test_url = f"{self.target}/?id={payload}"
                try:
                    r = self.session.get(test_url, timeout=5)
                    response_lower = r.text.lower()

                    for indicator in self.SQLI_INDICATORS:
                        if indicator in response_lower:
                            self.results["vulnerabilities"].append({
                                "type": "sqli",
                                "severity": "critical",
                                "title": "Potential SQL Injection",
                                "description": f"SQL error indicator found: '{indicator}'",
                                "evidence": f"Payload: {payload}, URL: {test_url}",
                                "remediation": "Use parameterized queries / prepared statements."
                            })
                            self._log(f"  [VULN] SQL injection indicator: {indicator}")
                            return
                except Exception:
                    continue

        except Exception as e:
            self._log(f"  [ERROR] SQLi check failed: {e}")

    def run(self):
        """Execute full web scan."""
        self._log(f"Starting web scan on {self.target}")
        self.check_headers()
        self.detect_technologies()
        self.enumerate_directories()
        self.check_ssl()
        self.check_xss()
        self.check_sqli()
        self._log(f"Web scan complete: {len(self.results['vulnerabilities'])} issues found")
        return self.results

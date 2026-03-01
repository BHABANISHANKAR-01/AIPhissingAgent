"""
Agent Loop — Autonomous scan orchestrator with AI-driven decision making.
"""
import threading
import time
from datetime import datetime
from backend import database as db
from backend.ai_engine import AIEngine
from backend.scanner.network_scanner import NetworkScanner
from backend.scanner.port_scanner import PortScanner
from backend.scanner.web_scanner import WebScanner
from backend.scanner.vuln_analyzer import VulnAnalyzer
from backend.config import SCAN_PROFILES


class AgentLoop:
    """Autonomous penetration testing agent."""

    def __init__(self):
        self.ai = AIEngine()
        self.active_scans = {}  # scan_id -> thread
        self._stop_flags = {}   # scan_id -> Event

    def start_scan(self, scan_id):
        """Start a scan in a background thread."""
        stop_event = threading.Event()
        self._stop_flags[scan_id] = stop_event
        thread = threading.Thread(target=self._run_scan, args=(scan_id, stop_event), daemon=True)
        self.active_scans[scan_id] = thread
        thread.start()

    def stop_scan(self, scan_id):
        """Signal a running scan to stop."""
        if scan_id in self._stop_flags:
            self._stop_flags[scan_id].set()

    def _log(self, scan_id, level, module, message):
        """Add a log entry for a scan."""
        try:
            db.add_log(scan_id, level, module, message)
        except Exception:
            pass

    def _run_scan(self, scan_id, stop_event):
        """Main scan execution loop."""
        scan = db.get_scan(scan_id)
        if not scan:
            return

        target = scan["target"]
        scan_type = scan["scan_type"]
        ai_enabled = scan["ai_enabled"]

        # Update status
        db.update_scan(scan_id, status="running", started_at=datetime.now().isoformat())
        self._log(scan_id, "info", "agent", f"═══ Scan initiated on {target} (type: {scan_type}) ═══")

        results = {}
        all_findings = []

        try:
            # ─── PHASE 0: AI Planning ──────────────────────────
            self._log(scan_id, "info", "agent", "Phase 0: Generating scan plan...")
            # Dynamically check if AI is available (key may have been set via Settings)
            ai_available = ai_enabled and bool(self.ai._resolve_api_key())
            if ai_available:
                self._log(scan_id, "info", "ai", "AI engine connected — generating intelligent scan plan...")
                plan = self.ai.generate_scan_plan(target, scan_type)
                self._log(scan_id, "info", "ai", f"Strategy: {plan.get('strategy', 'Standard methodology')}")
                self._log(scan_id, "info", "ai", f"Estimated duration: {plan.get('estimated_duration', 'Unknown')}")
                db.update_scan(scan_id, ai_plan=str(plan))
            else:
                plan = self.ai._default_plan(scan_type)
                if ai_enabled:
                    self._log(scan_id, "warn", "ai", "AI enabled but no API key found. Set your Groq API key in Settings. Using default plan.")
                else:
                    self._log(scan_id, "info", "agent", "Using default scan plan (AI disabled)")

            if stop_event.is_set():
                self._finalize_scan(scan_id, "cancelled", results, all_findings)
                return

            # Get profile
            profile = SCAN_PROFILES.get(scan_type, SCAN_PROFILES["standard"])
            modules = profile["modules"]

            # ─── PHASE 1: Network Reconnaissance ──────────────
            if "network_scan" in modules or scan_type == "deep":
                self._log(scan_id, "info", "network", "═══ Phase 1: Network Reconnaissance ═══")
                if stop_event.is_set():
                    self._finalize_scan(scan_id, "cancelled", results, all_findings)
                    return

                scanner = NetworkScanner(target, callback=lambda msg: self._log(scan_id, "info", "network", msg))
                net_results = scanner.run()
                results["network"] = net_results

            # ─── PHASE 2: Port Scanning ───────────────────────
            if "port_scan" in modules:
                self._log(scan_id, "info", "port", "═══ Phase 2: Port Scanning ═══")
                if stop_event.is_set():
                    self._finalize_scan(scan_id, "cancelled", results, all_findings)
                    return

                port_scanner = PortScanner(
                    target,
                    ports=profile["ports"],
                    timeout=profile["timeout"],
                    callback=lambda msg: self._log(scan_id, "info", "port", msg)
                )
                port_results = port_scanner.run()
                results["ports"] = port_results

            # ─── PHASE 3: Web Application Scanning ────────────
            if "web_scan" in modules:
                self._log(scan_id, "info", "web", "═══ Phase 3: Web Application Scanning ═══")
                if stop_event.is_set():
                    self._finalize_scan(scan_id, "cancelled", results, all_findings)
                    return

                web_scanner = WebScanner(target, callback=lambda msg: self._log(scan_id, "info", "web", msg))
                web_results = web_scanner.run()
                results["web"] = web_results

                # Add web vulnerabilities to findings
                for vuln in web_results.get("vulnerabilities", []):
                    finding_id = db.add_finding(
                        scan_id,
                        severity=vuln.get("severity", "info"),
                        category=vuln.get("type", "web"),
                        title=vuln.get("title", "Unknown"),
                        description=vuln.get("description", ""),
                        evidence=vuln.get("evidence", ""),
                        remediation=vuln.get("remediation", ""),
                        cvss_score={"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.0}.get(vuln.get("severity", "info"), 0)
                    )
                    all_findings.append(vuln)

            # ─── PHASE 4: Vulnerability Analysis ──────────────
            if "vuln_analysis" in modules and results.get("ports"):
                self._log(scan_id, "info", "vuln", "═══ Phase 4: Vulnerability Analysis ═══")
                if stop_event.is_set():
                    self._finalize_scan(scan_id, "cancelled", results, all_findings)
                    return

                analyzer = VulnAnalyzer(callback=lambda msg: self._log(scan_id, "info", "vuln", msg))
                vuln_findings = analyzer.run(results["ports"])
                results["vulnerabilities"] = vuln_findings

                for finding in vuln_findings:
                    finding_id = db.add_finding(
                        scan_id,
                        severity=finding.get("severity", "info"),
                        category=finding.get("category", "general"),
                        title=finding.get("title", "Unknown"),
                        description=finding.get("description", ""),
                        evidence=finding.get("evidence", ""),
                        remediation=finding.get("remediation", ""),
                        cvss_score=finding.get("cvss_score", 0),
                        cve_id=finding.get("cve_id", ""),
                        port=finding.get("port", 0),
                        service=finding.get("service", "")
                    )
                    all_findings.append(finding)

            # ─── PHASE 5: AI Analysis ─────────────────────────
            # Re-check AI availability (key might have been resolved during scan)
            ai_available = ai_enabled and bool(self.ai._resolve_api_key())
            if ai_available:
                self._log(scan_id, "info", "ai", "═══ Phase 5: AI-Powered Analysis ═══")
                try:
                    analysis = self.ai.analyze_results(target, results)
                    if analysis and not str(analysis).startswith("[AI Error]"):
                        self._log(scan_id, "info", "ai", f"AI Assessment:\n{analysis}")
                    else:
                        self._log(scan_id, "warn", "ai", f"AI analysis returned error: {analysis}")
                except Exception as ai_err:
                    self._log(scan_id, "error", "ai", f"AI analysis failed: {str(ai_err)}")

                # Generate enhanced remediation for critical findings
                try:
                    critical_findings = db.get_findings(scan_id)
                    for f in critical_findings:
                        if f["severity"] in ("critical", "high"):
                            ai_remediation = self.ai.generate_remediation(f)
                            if ai_remediation and not ai_remediation.startswith("[AI Error]"):
                                self._log(scan_id, "info", "ai", f"AI Remediation for '{f['title']}': {ai_remediation[:200]}")
                except Exception as rem_err:
                    self._log(scan_id, "error", "ai", f"AI remediation failed: {str(rem_err)}")
            elif ai_enabled:
                self._log(scan_id, "warn", "ai", "Skipping AI analysis — no API key configured. Add your Groq key in Settings.")

            # ─── Finalize ─────────────────────────────────────
            self._finalize_scan(scan_id, "completed", results, all_findings)

        except Exception as e:
            self._log(scan_id, "error", "agent", f"Scan failed with error: {str(e)}")
            self._finalize_scan(scan_id, "failed", results, all_findings)

    def _finalize_scan(self, scan_id, status, results, findings):
        """Finalize the scan and generate summary."""
        scan = db.get_scan(scan_id)
        started = scan.get("started_at", "")

        # Calculate duration
        duration = "Unknown"
        if started:
            try:
                start_time = datetime.fromisoformat(started)
                duration = str(datetime.now() - start_time).split(".")[0]
            except Exception:
                pass

        # Generate summary
        severity_counts = {}
        for f in findings:
            sev = f.get("severity", "info")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        open_ports = len(results.get("ports", []))
        summary = (
            f"Scan {status}. Duration: {duration}. "
            f"Open ports: {open_ports}. "
            f"Findings: {len(findings)} total "
            f"(Critical: {severity_counts.get('critical', 0)}, "
            f"High: {severity_counts.get('high', 0)}, "
            f"Medium: {severity_counts.get('medium', 0)}, "
            f"Low: {severity_counts.get('low', 0)})"
        )

        db.update_scan(scan_id, status=status, completed_at=datetime.now().isoformat(), summary=summary)
        self._log(scan_id, "info", "agent", f"═══ {summary} ═══")

        # Cleanup
        self.active_scans.pop(scan_id, None)
        self._stop_flags.pop(scan_id, None)


# Singleton agent
agent = AgentLoop()

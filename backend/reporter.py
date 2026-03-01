"""
Report Generator — HTML and JSON report generation.
"""
import json
from datetime import datetime
from backend import database as db
from backend.ai_engine import AIEngine


class Reporter:
    """Generate penetration test reports."""

    def __init__(self):
        self.ai = AIEngine()

    def generate_html_report(self, scan_id):
        """Generate a comprehensive HTML report."""
        scan = db.get_scan(scan_id)
        if not scan:
            return None

        findings = db.get_findings(scan_id)
        logs = db.get_logs(scan_id)

        # Severity counts
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.get("severity", "info")
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        # Calculate duration
        duration = "N/A"
        if scan.get("started_at") and scan.get("completed_at"):
            try:
                start = datetime.fromisoformat(scan["started_at"])
                end = datetime.fromisoformat(scan["completed_at"])
                duration = str(end - start).split(".")[0]
            except Exception:
                pass

        # Executive summary
        exec_summary = scan.get("summary", "No summary available.")
        if self.ai.available:
            try:
                exec_summary = self.ai.generate_executive_summary(
                    scan["target"], findings, duration
                )
            except Exception:
                pass

        # Build HTML
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Penetration Test Report — {scan['target']}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0a0e1a; color: #c8d6e5; line-height: 1.6; padding: 40px; }}
        .container {{ max-width: 1000px; margin: 0 auto; }}
        h1 {{ color: #00d4ff; font-size: 28px; border-bottom: 2px solid #1a2744; padding-bottom: 15px; margin-bottom: 30px; }}
        h2 {{ color: #00ff88; font-size: 20px; margin: 30px 0 15px; padding-bottom: 8px; border-bottom: 1px solid #1a2744; }}
        h3 {{ color: #e2e8f0; font-size: 16px; margin: 20px 0 10px; }}
        .meta {{ background: #111827; border-radius: 10px; padding: 20px; margin-bottom: 30px; border: 1px solid #1a2744; }}
        .meta-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; }}
        .meta-item {{ padding: 10px; }}
        .meta-label {{ font-size: 12px; color: #64748b; text-transform: uppercase; letter-spacing: 1px; }}
        .meta-value {{ font-size: 18px; font-weight: 600; color: #e2e8f0; }}
        .severity-bar {{ display: flex; gap: 10px; margin: 20px 0; flex-wrap: wrap; }}
        .sev-badge {{ padding: 8px 16px; border-radius: 8px; font-weight: 600; font-size: 14px; }}
        .sev-critical {{ background: rgba(255,51,102,0.2); color: #ff3366; border: 1px solid #ff3366; }}
        .sev-high {{ background: rgba(255,107,53,0.2); color: #ff6b35; border: 1px solid #ff6b35; }}
        .sev-medium {{ background: rgba(255,193,7,0.2); color: #ffc107; border: 1px solid #ffc107; }}
        .sev-low {{ background: rgba(0,212,255,0.2); color: #00d4ff; border: 1px solid #00d4ff; }}
        .sev-info {{ background: rgba(100,116,139,0.2); color: #94a3b8; border: 1px solid #64748b; }}
        .summary {{ background: #111827; border-radius: 10px; padding: 25px; margin: 20px 0; border-left: 4px solid #00d4ff; }}
        .finding {{ background: #111827; border-radius: 10px; padding: 20px; margin: 15px 0; border: 1px solid #1a2744; }}
        .finding-header {{ display: flex; align-items: center; gap: 10px; margin-bottom: 10px; }}
        .finding-title {{ font-weight: 600; color: #e2e8f0; flex: 1; }}
        .detail {{ margin: 8px 0; font-size: 14px; }}
        .detail-label {{ color: #64748b; font-weight: 600; }}
        .evidence {{ background: #0a0e1a; padding: 10px; border-radius: 6px; font-family: monospace; font-size: 13px; margin: 8px 0; word-break: break-all; }}
        .footer {{ text-align: center; margin-top: 50px; padding-top: 20px; border-top: 1px solid #1a2744; color: #64748b; font-size: 12px; }}
        .disclaimer {{ background: rgba(255,193,7,0.1); border: 1px solid #ffc107; border-radius: 10px; padding: 15px; margin: 20px 0; color: #ffc107; font-size: 13px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Penetration Test Report</h1>
        
        <div class="disclaimer">
            ⚠️ CONFIDENTIAL — This report contains sensitive security findings. For authorized personnel only.
            This assessment was performed in a controlled environment for educational purposes.
        </div>

        <div class="meta">
            <div class="meta-grid">
                <div class="meta-item">
                    <div class="meta-label">Target</div>
                    <div class="meta-value">{scan['target']}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Scan Type</div>
                    <div class="meta-value">{scan['scan_type'].title()}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Duration</div>
                    <div class="meta-value">{duration}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Status</div>
                    <div class="meta-value">{scan['status'].title()}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Total Findings</div>
                    <div class="meta-value">{len(findings)}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Date</div>
                    <div class="meta-value">{scan.get('completed_at', scan.get('created_at', 'N/A'))[:10]}</div>
                </div>
            </div>
        </div>

        <h2>Severity Breakdown</h2>
        <div class="severity-bar">
            <span class="sev-badge sev-critical">Critical: {sev_counts['critical']}</span>
            <span class="sev-badge sev-high">High: {sev_counts['high']}</span>
            <span class="sev-badge sev-medium">Medium: {sev_counts['medium']}</span>
            <span class="sev-badge sev-low">Low: {sev_counts['low']}</span>
            <span class="sev-badge sev-info">Info: {sev_counts['info']}</span>
        </div>

        <h2>Executive Summary</h2>
        <div class="summary">{exec_summary}</div>

        <h2>Findings ({len(findings)})</h2>
"""

        # Sort findings by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.get("severity", "info"), 5))

        for f in sorted_findings:
            sev = f.get("severity", "info")
            html += f"""
        <div class="finding">
            <div class="finding-header">
                <span class="sev-badge sev-{sev}">{sev.upper()}</span>
                <span class="finding-title">{f.get('title', 'Unknown')}</span>
            </div>
            <div class="detail"><span class="detail-label">Description:</span> {f.get('description', 'N/A')}</div>
            {"<div class='detail'><span class='detail-label'>CVE:</span> " + f['cve_id'] + "</div>" if f.get('cve_id') else ""}
            {"<div class='detail'><span class='detail-label'>CVSS Score:</span> " + str(f['cvss_score']) + "</div>" if f.get('cvss_score') else ""}
            {"<div class='detail'><span class='detail-label'>Port:</span> " + str(f['port']) + " (" + f.get('service', '') + ")</div>" if f.get('port') else ""}
            {"<div class='evidence'>" + f['evidence'] + "</div>" if f.get('evidence') else ""}
            <div class="detail"><span class="detail-label">Remediation:</span> {f.get('remediation', 'Review and patch the affected service.')}</div>
        </div>
"""

        html += f"""
        <div class="footer">
            <p>Generated by AI Penetration Testing Assistant — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>For educational and authorized use only.</p>
        </div>
    </div>
</body>
</html>"""

        # Save report
        report_id = db.save_report(scan_id, "html", html)
        return html

    def generate_json_report(self, scan_id):
        """Generate a JSON report."""
        scan = db.get_scan(scan_id)
        if not scan:
            return None

        findings = db.get_findings(scan_id)

        report = {
            "meta": {
                "target": scan["target"],
                "scan_type": scan["scan_type"],
                "status": scan["status"],
                "started_at": scan.get("started_at"),
                "completed_at": scan.get("completed_at"),
                "generated_at": datetime.now().isoformat()
            },
            "summary": scan.get("summary", ""),
            "findings": findings,
            "total_findings": len(findings)
        }

        content = json.dumps(report, indent=2)
        db.save_report(scan_id, "json", content)
        return report

"""
Flask Application — REST API and SSE for the AI Penetration Testing Assistant.
"""
import json
import time
import os
from flask import Flask, request, jsonify, Response, send_from_directory
from flask_cors import CORS
from backend import database as db
from backend.agent_loop import agent
from backend.reporter import Reporter
from backend.config import HOST, PORT, DEBUG
from backend.scanner.exploit_verifier import ExploitVerifier


# ─── App Setup ──────────────────────────────────────────────────
app = Flask(__name__, static_folder=None)
CORS(app)

FRONTEND_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "frontend")
reporter = Reporter()
exploiter = ExploitVerifier()


# ─── Initialize DB on startup ──────────────────────────────────
with app.app_context():
    db.init_db()


# ─── Static File Serving (Frontend) ────────────────────────────

@app.route("/")
def index():
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.route("/<path:filename>")
def static_files(filename):
    return send_from_directory(FRONTEND_DIR, filename)


# ─── Dashboard API ─────────────────────────────────────────────

@app.route("/api/dashboard")
def dashboard():
    stats = db.get_dashboard_stats()
    return jsonify(stats)


# ─── Scan API ──────────────────────────────────────────────────

@app.route("/api/scans", methods=["GET"])
def list_scans():
    scans = db.get_all_scans()
    return jsonify(scans)


@app.route("/api/scans", methods=["POST"])
def create_scan():
    data = request.get_json()
    if not data or not data.get("target"):
        return jsonify({"error": "Target is required"}), 400

    target = data["target"].strip()
    scan_type = data.get("scan_type", "standard")
    ai_enabled = data.get("ai_enabled", True)
    config = data.get("config", {})

    scan_id = db.create_scan(target, scan_type, ai_enabled, config)

    # Start the scan in background
    agent.start_scan(scan_id)

    return jsonify({"id": scan_id, "status": "started", "message": f"Scan {scan_id} started on {target}"}), 201


@app.route("/api/scans/<int:scan_id>")
def get_scan(scan_id):
    scan = db.get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    findings = db.get_findings(scan_id)
    scan["findings"] = findings
    scan["finding_count"] = len(findings)

    return jsonify(scan)


@app.route("/api/scans/<int:scan_id>", methods=["DELETE"])
def delete_scan(scan_id):
    scan = db.get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    # Stop if running
    if scan["status"] == "running":
        agent.stop_scan(scan_id)

    db.delete_scan(scan_id)
    return jsonify({"message": f"Scan {scan_id} deleted"})


@app.route("/api/scans/<int:scan_id>/stop", methods=["POST"])
def stop_scan(scan_id):
    scan = db.get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    agent.stop_scan(scan_id)
    return jsonify({"message": f"Scan {scan_id} stop signal sent"})


# ─── SSE Log Stream ────────────────────────────────────────────

@app.route("/api/scans/<int:scan_id>/logs")
def stream_logs(scan_id):
    """Server-Sent Events stream for real-time scan logs."""
    def generate():
        last_id = 0
        while True:
            logs = db.get_logs(scan_id, after_id=last_id)
            for log in logs:
                last_id = log["id"]
                event_data = json.dumps({
                    "id": log["id"],
                    "level": log["level"],
                    "module": log["module"],
                    "message": log["message"],
                    "timestamp": log["created_at"]
                })
                yield f"data: {event_data}\n\n"

            # Check if scan is done
            scan = db.get_scan(scan_id)
            if scan and scan["status"] in ("completed", "failed", "cancelled"):
                # Send any remaining logs
                remaining = db.get_logs(scan_id, after_id=last_id)
                for log in remaining:
                    event_data = json.dumps({
                        "id": log["id"],
                        "level": log["level"],
                        "module": log["module"],
                        "message": log["message"],
                        "timestamp": log["created_at"]
                    })
                    yield f"data: {event_data}\n\n"

                yield f"data: {json.dumps({'type': 'complete', 'status': scan['status']})}\n\n"
                break

            time.sleep(0.5)

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ─── Findings API ──────────────────────────────────────────────

@app.route("/api/findings")
def all_findings():
    findings = db.get_all_findings()
    return jsonify(findings)


@app.route("/api/scans/<int:scan_id>/findings")
def scan_findings(scan_id):
    findings = db.get_findings(scan_id)
    return jsonify(findings)


# ─── Report API ────────────────────────────────────────────────

@app.route("/api/reports/<int:scan_id>")
def get_report(scan_id):
    format_type = request.args.get("format", "html")

    if format_type == "json":
        report = reporter.generate_json_report(scan_id)
        if report:
            return jsonify(report)
    else:
        html = reporter.generate_html_report(scan_id)
        if html:
            return Response(html, mimetype="text/html")

    return jsonify({"error": "Could not generate report"}), 404


# ─── Exploit Verification API ─────────────────────────────────

@app.route("/api/exploit/verify", methods=["POST"])
def exploit_verify():
    """Verify a single finding by attempting PoC exploitation."""
    data = request.get_json()
    if not data or not data.get("finding_id"):
        return jsonify({"error": "finding_id is required"}), 400

    finding_id = data["finding_id"]

    # Get the finding
    conn = db.get_connection()
    row = conn.execute("SELECT f.*, s.target FROM findings f JOIN scans s ON f.scan_id = s.id WHERE f.id = ?", (finding_id,)).fetchone()
    conn.close()

    if not row:
        return jsonify({"error": "Finding not found"}), 404

    finding = dict(row)
    target = finding.pop("target")

    # Run the exploit verifier
    verifier = ExploitVerifier(callback=lambda msg: print(f"[Exploit] {msg}"))
    result = verifier.verify_finding(finding, target)

    return jsonify({
        "finding_id": finding_id,
        "finding_title": finding.get("title", "Unknown"),
        "target": target,
        "result": result
    })


@app.route("/api/exploit/verify-all/<int:scan_id>", methods=["POST"])
def exploit_verify_all(scan_id):
    """Verify all findings for a scan."""
    scan = db.get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    findings = db.get_findings(scan_id)
    target = scan["target"]

    verifier = ExploitVerifier(callback=lambda msg: print(f"[Exploit] {msg}"))
    results = []

    for finding in findings:
        result = verifier.verify_finding(finding, target)
        results.append({
            "finding_id": finding["id"],
            "finding_title": finding.get("title", "Unknown"),
            "severity": finding.get("severity", "info"),
            "result": result
        })

    verified = sum(1 for r in results if r["result"].get("success"))
    return jsonify({
        "scan_id": scan_id,
        "target": target,
        "total_findings": len(findings),
        "verified_exploitable": verified,
        "results": results
    })


@app.route("/api/exploit/poc/<int:finding_id>")
def exploit_poc_page(finding_id):
    """Serve the PoC HTML page for a verified exploit."""
    conn = db.get_connection()
    row = conn.execute("SELECT f.*, s.target FROM findings f JOIN scans s ON f.scan_id = s.id WHERE f.id = ?", (finding_id,)).fetchone()
    conn.close()

    if not row:
        return "Finding not found", 404

    finding = dict(row)
    target = finding.pop("target")

    verifier = ExploitVerifier()
    result = verifier.verify_finding(finding, target)

    if result.get("poc_html"):
        return Response(result["poc_html"], mimetype="text/html")

    # Default PoC page
    from backend.scanner.exploit_verifier import HACK_MESSAGE_HTML
    return Response(HACK_MESSAGE_HTML, mimetype="text/html")


# ─── Settings API ──────────────────────────────────────────────

@app.route("/api/settings", methods=["GET"])
def get_settings():
    settings = {
        "groq_api_key": db.get_setting("groq_api_key", ""),
        "default_scan_type": db.get_setting("default_scan_type", "standard"),
        "max_threads": db.get_setting("max_threads", "50"),
        "scan_timeout": db.get_setting("scan_timeout", "3"),
    }
    # Mask API key
    if settings["groq_api_key"]:
        key = settings["groq_api_key"]
        settings["groq_api_key_masked"] = key[:8] + "..." + key[-4:] if len(key) > 12 else "***"
    return jsonify(settings)


@app.route("/api/settings", methods=["PUT"])
def update_settings():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400

    for key, value in data.items():
        db.set_setting(key, str(value))

    # Update AI engine if API key changed
    if "groq_api_key" in data:
        from backend.ai_engine import AIEngine
        agent.ai = AIEngine(api_key=data["groq_api_key"])

    return jsonify({"message": "Settings updated"})


# ─── Health Check ──────────────────────────────────────────────

@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "version": "1.0.0"})


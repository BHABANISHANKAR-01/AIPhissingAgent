"""
SQLite database layer for the AI Penetration Testing Assistant.
"""
import sqlite3
import os
import json
from datetime import datetime
from backend.config import DATABASE_PATH


def get_db_path():
    """Ensure data directory exists and return DB path."""
    db_dir = os.path.dirname(DATABASE_PATH)
    os.makedirs(db_dir, exist_ok=True)
    return DATABASE_PATH


def get_connection():
    """Get a new database connection."""
    conn = sqlite3.connect(get_db_path())
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    """Initialize the database schema."""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.executescript("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            scan_type TEXT NOT NULL DEFAULT 'standard',
            status TEXT NOT NULL DEFAULT 'pending',
            ai_enabled INTEGER NOT NULL DEFAULT 1,
            config TEXT DEFAULT '{}',
            ai_plan TEXT DEFAULT '',
            summary TEXT DEFAULT '',
            started_at TEXT,
            completed_at TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            severity TEXT NOT NULL DEFAULT 'info',
            category TEXT NOT NULL DEFAULT 'general',
            title TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            evidence TEXT DEFAULT '',
            remediation TEXT DEFAULT '',
            cvss_score REAL DEFAULT 0.0,
            cve_id TEXT DEFAULT '',
            port INTEGER DEFAULT 0,
            service TEXT DEFAULT '',
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS scan_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            level TEXT NOT NULL DEFAULT 'info',
            module TEXT NOT NULL DEFAULT 'core',
            message TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            format TEXT NOT NULL DEFAULT 'html',
            content TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
    """)

    conn.commit()
    conn.close()


# ─── Scan Operations ──────────────────────────────────────────

def create_scan(target, scan_type="standard", ai_enabled=True, config=None):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO scans (target, scan_type, ai_enabled, config, status) VALUES (?, ?, ?, ?, 'pending')",
        (target, scan_type, 1 if ai_enabled else 0, json.dumps(config or {}))
    )
    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return scan_id


def update_scan(scan_id, **kwargs):
    conn = get_connection()
    sets = []
    vals = []
    for k, v in kwargs.items():
        sets.append(f"{k} = ?")
        vals.append(v)
    vals.append(scan_id)
    conn.execute(f"UPDATE scans SET {', '.join(sets)} WHERE id = ?", vals)
    conn.commit()
    conn.close()


def get_scan(scan_id):
    conn = get_connection()
    row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def get_all_scans():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM scans ORDER BY created_at DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def delete_scan(scan_id):
    conn = get_connection()
    conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    conn.commit()
    conn.close()


# ─── Finding Operations ────────────────────────────────────────

def add_finding(scan_id, severity, category, title, description="", evidence="",
                remediation="", cvss_score=0.0, cve_id="", port=0, service=""):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """INSERT INTO findings 
        (scan_id, severity, category, title, description, evidence, remediation, cvss_score, cve_id, port, service) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (scan_id, severity, category, title, description, evidence, remediation, cvss_score, cve_id, port, service)
    )
    finding_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return finding_id


def get_findings(scan_id):
    conn = get_connection()
    rows = conn.execute("SELECT * FROM findings WHERE scan_id = ? ORDER BY cvss_score DESC", (scan_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_all_findings():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM findings ORDER BY cvss_score DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ─── Log Operations ───────────────────────────────────────────

def add_log(scan_id, level, module, message):
    conn = get_connection()
    conn.execute(
        "INSERT INTO scan_logs (scan_id, level, module, message) VALUES (?, ?, ?, ?)",
        (scan_id, level, module, message)
    )
    conn.commit()
    conn.close()


def get_logs(scan_id, after_id=0):
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM scan_logs WHERE scan_id = ? AND id > ? ORDER BY id ASC",
        (scan_id, after_id)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ─── Report Operations ────────────────────────────────────────

def save_report(scan_id, format_type, content):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO reports (scan_id, format, content) VALUES (?, ?, ?)",
        (scan_id, format_type, content)
    )
    report_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return report_id


def get_report(scan_id):
    conn = get_connection()
    row = conn.execute("SELECT * FROM reports WHERE scan_id = ? ORDER BY created_at DESC LIMIT 1", (scan_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


# ─── Settings Operations ──────────────────────────────────────

def get_setting(key, default=None):
    conn = get_connection()
    row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    conn.close()
    return row["value"] if row else default


def set_setting(key, value):
    conn = get_connection()
    conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value))
    conn.commit()
    conn.close()


# ─── Dashboard Stats ──────────────────────────────────────────

def get_dashboard_stats():
    conn = get_connection()
    stats = {}

    row = conn.execute("SELECT COUNT(*) as total FROM scans").fetchone()
    stats["total_scans"] = row["total"]

    row = conn.execute("SELECT COUNT(*) as c FROM scans WHERE status = 'running'").fetchone()
    stats["active_scans"] = row["c"]

    row = conn.execute("SELECT COUNT(*) as c FROM scans WHERE status = 'completed'").fetchone()
    stats["completed_scans"] = row["c"]

    row = conn.execute("SELECT COUNT(*) as c FROM findings").fetchone()
    stats["total_findings"] = row["c"]

    severity_rows = conn.execute(
        "SELECT severity, COUNT(*) as c FROM findings GROUP BY severity"
    ).fetchall()
    stats["severity_breakdown"] = {r["severity"]: r["c"] for r in severity_rows}

    recent = conn.execute(
        "SELECT * FROM scans ORDER BY created_at DESC LIMIT 5"
    ).fetchall()
    stats["recent_scans"] = [dict(r) for r in recent]

    conn.close()
    return stats

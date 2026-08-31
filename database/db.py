"""
database/db.py

SQLite database layer for the Web Application Security Scanner.

Responsible for:
- Creating the database schema (scans, findings tables)
- Providing simple helper functions used across the app
  (create scan, update scan status, insert finding, fetch data for
  the dashboard / results pages).

Plain sqlite3 is used (no ORM) to keep the project lightweight and
easy to read for portfolio / learning purposes.
"""

import sqlite3
import os
from contextlib import contextmanager
from datetime import datetime

# Database file lives alongside this module
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scanner.db")

SEVERITIES = ("High", "Medium", "Low", "Informational")


@contextmanager
def get_connection():
    """Context manager that yields a sqlite3 connection with row access by column name."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    """Create tables if they do not already exist. Safe to call on every startup."""
    with get_connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                date TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Queued',
                pages_discovered INTEGER DEFAULT 0,
                forms_discovered INTEGER DEFAULT 0,
                current_step TEXT DEFAULT '',
                progress INTEGER DEFAULT 0,
                error TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                vulnerability TEXT NOT NULL,
                severity TEXT NOT NULL,
                url TEXT,
                description TEXT,
                evidence TEXT,
                recommendation TEXT,
                category TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings (scan_id)"
        )


# ---------------------------------------------------------------------------
# Scan helpers
# ---------------------------------------------------------------------------

def create_scan(target: str) -> int:
    with get_connection() as conn:
        cur = conn.execute(
            "INSERT INTO scans (target, date, status, progress, current_step) "
            "VALUES (?, ?, 'Running', 0, 'Initializing')",
            (target, datetime.utcnow().isoformat(timespec="seconds") + "Z"),
        )
        return cur.lastrowid


def update_scan_progress(scan_id: int, progress: int, current_step: str):
    with get_connection() as conn:
        conn.execute(
            "UPDATE scans SET progress = ?, current_step = ? WHERE id = ?",
            (progress, current_step, scan_id),
        )


def update_scan_stats(scan_id: int, pages_discovered: int, forms_discovered: int):
    with get_connection() as conn:
        conn.execute(
            "UPDATE scans SET pages_discovered = ?, forms_discovered = ? WHERE id = ?",
            (pages_discovered, forms_discovered, scan_id),
        )


def complete_scan(scan_id: int, status: str = "Completed", error: str = None):
    with get_connection() as conn:
        conn.execute(
            "UPDATE scans SET status = ?, progress = 100, current_step = 'Done', error = ? WHERE id = ?",
            (status, error, scan_id),
        )


def get_scan(scan_id: int):
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        return dict(row) if row else None


def get_all_scans(limit: int = 100):
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Finding helpers
# ---------------------------------------------------------------------------

def add_finding(scan_id: int, vulnerability: str, severity: str, url: str = "",
                 description: str = "", evidence: str = "", recommendation: str = "",
                 category: str = "General"):
    if severity not in SEVERITIES:
        severity = "Informational"
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO findings
                (scan_id, vulnerability, severity, url, description, evidence, recommendation, category)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (scan_id, vulnerability, severity, url, description, evidence, recommendation, category),
        )


def get_findings(scan_id: int, severity: str = None):
    with get_connection() as conn:
        if severity and severity != "All":
            rows = conn.execute(
                "SELECT * FROM findings WHERE scan_id = ? AND severity = ? ORDER BY "
                "CASE severity WHEN 'High' THEN 0 WHEN 'Medium' THEN 1 WHEN 'Low' THEN 2 ELSE 3 END",
                (scan_id, severity),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM findings WHERE scan_id = ? ORDER BY "
                "CASE severity WHEN 'High' THEN 0 WHEN 'Medium' THEN 1 WHEN 'Low' THEN 2 ELSE 3 END",
                (scan_id,),
            ).fetchall()
        return [dict(r) for r in rows]


def get_severity_counts(scan_id: int = None):
    """Return counts of High/Medium/Low/Informational findings.
    If scan_id is None, counts across ALL scans (used for the dashboard)."""
    counts = {s: 0 for s in SEVERITIES}
    with get_connection() as conn:
        if scan_id is None:
            rows = conn.execute(
                "SELECT severity, COUNT(*) as c FROM findings GROUP BY severity"
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT severity, COUNT(*) as c FROM findings WHERE scan_id = ? GROUP BY severity",
                (scan_id,),
            ).fetchall()
        for r in rows:
            counts[r["severity"]] = r["c"]
    return counts


def get_dashboard_stats():
    with get_connection() as conn:
        total_scans = conn.execute("SELECT COUNT(*) c FROM scans").fetchone()["c"]
        total_findings = conn.execute("SELECT COUNT(*) c FROM findings").fetchone()["c"]
        recent_scans = conn.execute(
            "SELECT * FROM scans ORDER BY id DESC LIMIT 8"
        ).fetchall()
    severity_counts = get_severity_counts()
    return {
        "total_scans": total_scans,
        "total_findings": total_findings,
        "high": severity_counts["High"],
        "medium": severity_counts["Medium"],
        "low": severity_counts["Low"],
        "info": severity_counts["Informational"],
        "recent_scans": [dict(r) for r in recent_scans],
    }

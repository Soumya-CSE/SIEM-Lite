import os
import json
import sqlite3
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
DB_PATH = os.path.join(DATA_DIR, "siem_lite.db")

# Server "uptime" is measured from when this module was first imported
# (i.e. when the Flask process started).
APP_STARTED_AT = datetime.now()

DEFAULT_SETTINGS = {
    "high_risk_threshold": 3,
    "medium_risk_threshold": 2,
    "history_retention": 25,
    "alerts_enabled": True,
    "alert_email": ""
}


def _connect():
    os.makedirs(DATA_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    conn = _connect()
    try:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                uploaded_at TEXT NOT NULL,
                threat_score INTEGER NOT NULL,
                failed_logins INTEGER NOT NULL,
                suspicious_ips INTEGER NOT NULL,
                critical_events INTEGER NOT NULL,
                total_events INTEGER NOT NULL,
                result_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS acknowledged_alerts (
                key TEXT PRIMARY KEY,
                acknowledged_at TEXT NOT NULL
            );
        """)
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------- settings --

def get_settings():
    conn = _connect()
    try:
        rows = conn.execute("SELECT key, value FROM settings").fetchall()
    finally:
        conn.close()
    stored = {row["key"]: json.loads(row["value"]) for row in rows}
    merged = dict(DEFAULT_SETTINGS)
    merged.update(stored)
    return merged


def update_settings(patch):
    current = get_settings()

    def as_int(name, value, lo, hi):
        try:
            n = int(value)
        except (TypeError, ValueError):
            raise ValueError(name + " must be a whole number")
        if n < lo or n > hi:
            raise ValueError(name + " must be between " + str(lo) + " and " + str(hi))
        return n

    if "high_risk_threshold" in patch:
        current["high_risk_threshold"] = as_int("high_risk_threshold", patch["high_risk_threshold"], 2, 50)
    if "medium_risk_threshold" in patch:
        current["medium_risk_threshold"] = as_int("medium_risk_threshold", patch["medium_risk_threshold"], 1, 49)
    if current["medium_risk_threshold"] >= current["high_risk_threshold"]:
        raise ValueError("medium_risk_threshold must be lower than high_risk_threshold")

    if "history_retention" in patch:
        current["history_retention"] = as_int("history_retention", patch["history_retention"], 1, 500)

    if "alerts_enabled" in patch:
        current["alerts_enabled"] = bool(patch["alerts_enabled"])

    if "alert_email" in patch:
        email = str(patch["alert_email"] or "").strip()
        if len(email) > 200:
            raise ValueError("alert_email is too long")
        current["alert_email"] = email

    conn = _connect()
    try:
        for key, value in current.items():
            conn.execute(
                "INSERT INTO settings (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, json.dumps(value))
            )
        conn.commit()
    finally:
        conn.close()

    # Retention may have shrunk - prune immediately so History reflects it.
    _prune_history(current["history_retention"])
    return current


# ------------------------------------------------------------------ scans --

def save_scan(filename, result):
    uploaded_at = datetime.now().isoformat(timespec="seconds")
    conn = _connect()
    try:
        prev_row = conn.execute(
            "SELECT threat_score, failed_logins, suspicious_ips, critical_events, total_events "
            "FROM scans ORDER BY id DESC LIMIT 1"
        ).fetchone()
        cur = conn.execute(
            "INSERT INTO scans "
            "(filename, uploaded_at, threat_score, failed_logins, suspicious_ips, "
            " critical_events, total_events, result_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                filename,
                uploaded_at,
                result.get("threatScore", 0),
                result.get("failedLogins", 0),
                result.get("suspiciousIps", 0),
                result.get("criticalEvents", 0),
                result.get("totalEvents", 0),
                json.dumps(result)
            )
        )
        conn.commit()
        scan_id = cur.lastrowid
    finally:
        conn.close()

    retention = get_settings()["history_retention"]
    _prune_history(retention)

    previous = None
    if prev_row:
        previous = {
            "threatScore": prev_row["threat_score"],
            "failedLogins": prev_row["failed_logins"],
            "suspiciousIps": prev_row["suspicious_ips"],
            "criticalEvents": prev_row["critical_events"],
            "totalEvents": prev_row["total_events"]
        }
    return scan_id, uploaded_at, previous


def _prune_history(retention):
    conn = _connect()
    try:
        ids = [r["id"] for r in conn.execute("SELECT id FROM scans ORDER BY id DESC")]
        stale = ids[retention:]
        if stale:
            placeholders = ",".join("?" for _ in stale)
            conn.execute("DELETE FROM scans WHERE id IN (" + placeholders + ")", stale)
            conn.commit()
    finally:
        conn.close()


def list_history(limit=None):
    conn = _connect()
    try:
        sql = ("SELECT id, filename, uploaded_at, threat_score, failed_logins, "
               "suspicious_ips, critical_events, total_events FROM scans ORDER BY id DESC")
        if limit:
            sql += " LIMIT ?"
            rows = conn.execute(sql, (limit,)).fetchall()
        else:
            rows = conn.execute(sql).fetchall()
    finally:
        conn.close()
    return [
        {
            "id": r["id"],
            "filename": r["filename"],
            "uploadedAt": r["uploaded_at"],
            "threatScore": r["threat_score"],
            "failedLogins": r["failed_logins"],
            "suspiciousIps": r["suspicious_ips"],
            "criticalEvents": r["critical_events"],
            "totalEvents": r["total_events"]
        }
        for r in rows
    ]


def get_scan(scan_id):
    conn = _connect()
    try:
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    finally:
        conn.close()
    if not row:
        return None
    result = json.loads(row["result_json"])
    result["id"] = row["id"]
    result["filename"] = row["filename"]
    result["uploadedAt"] = row["uploaded_at"]
    return result


def delete_scan(scan_id):
    conn = _connect()
    try:
        cur = conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def clear_history():
    conn = _connect()
    try:
        conn.execute("DELETE FROM scans")
        conn.execute("DELETE FROM acknowledged_alerts")
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------- alerts --

def list_alerts(scan_limit=20):
    conn = _connect()
    try:
        rows = conn.execute(
            "SELECT id, filename, uploaded_at, result_json FROM scans "
            "ORDER BY id DESC LIMIT ?", (scan_limit,)
        ).fetchall()
        acked = {r["key"] for r in conn.execute("SELECT key FROM acknowledged_alerts")}
    finally:
        conn.close()

    alerts = []
    for row in rows:
        result = json.loads(row["result_json"])
        scan_id = row["id"]

        for i, ev in enumerate(result.get("criticalEventRows", [])):
            key = "crit:{}:{}".format(scan_id, i)
            if key in acked:
                continue
            alerts.append({
                "key": key,
                "severity": "critical",
                "title": ev.get("title", "Critical event"),
                "time": ev.get("time", row["uploaded_at"]),
                "sourceFile": row["filename"],
                "scanId": scan_id
            })

        for i, su in enumerate(result.get("suspicious", [])):
            if su.get("level") != "HIGH":
                continue
            key = "user:{}:{}".format(scan_id, i)
            if key in acked:
                continue
            alerts.append({
                "key": key,
                "severity": "high",
                "title": "Repeated failed logins for user '{}' ({} attempts)".format(
                    su.get("user", "unknown"), su.get("attempts", 0)
                ),
                "time": row["uploaded_at"],
                "sourceFile": row["filename"],
                "scanId": scan_id
            })

    return alerts


def acknowledge_alert(key):
    conn = _connect()
    try:
        conn.execute(
            "INSERT INTO acknowledged_alerts (key, acknowledged_at) VALUES (?, ?) "
            "ON CONFLICT(key) DO NOTHING",
            (key, datetime.now().isoformat(timespec="seconds"))
        )
        conn.commit()
    finally:
        conn.close()


# ----------------------------------------------------------------- about --

def get_about_stats():
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT COUNT(*) AS n, COALESCE(SUM(total_events), 0) AS total FROM scans"
        ).fetchone()
    finally:
        conn.close()
    return {
        "version": "1.0",
        "totalScans": row["n"],
        "totalEventsProcessed": row["total"],
        "startedAt": APP_STARTED_AT.isoformat(timespec="seconds")
    }

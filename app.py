from flask import Flask, render_template, request, jsonify
import os
from datetime import datetime
from analyzer import analyze_logs
import storage
import mailer

app = Flask(__name__)

# Get the directory containing app.py
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Create the full path to the uploads folder
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")

# Create the folder if it doesn't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# Create the SQLite tables (scans / settings / acknowledged_alerts) if missing
storage.init_db()


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    file = request.files.get("logfile")
    if not file:
        return jsonify({"error": "No file uploaded"}), 400

    settings = storage.get_settings()

    try:
        result = analyze_logs(
            file.stream,
            high_threshold=settings["high_risk_threshold"],
            medium_threshold=settings["medium_risk_threshold"]
        )
    except Exception:
        return jsonify({"error": "Unable to parse uploaded log file"}), 400

    filename = file.filename or "uploaded.log"
    scan_id, uploaded_at, previous_scan = storage.save_scan(filename, result)
    result["id"] = scan_id
    result["filename"] = filename
    result["uploadedAt"] = uploaded_at
    result["previousScan"] = previous_scan

    return jsonify(result)


# ------------------------------------------------------------ Analysis History --

@app.route("/api/history", methods=["GET"])
def api_history_list():
    limit = request.args.get("limit", type=int)
    return jsonify(storage.list_history(limit))


@app.route("/api/history/<int:scan_id>", methods=["GET"])
def api_history_detail(scan_id):
    record = storage.get_scan(scan_id)
    if not record:
        return jsonify({"error": "Scan not found"}), 404
    return jsonify(record)


@app.route("/api/history/<int:scan_id>", methods=["DELETE"])
def api_history_delete(scan_id):
    if not storage.delete_scan(scan_id):
        return jsonify({"error": "Scan not found"}), 404
    return jsonify({"ok": True})


@app.route("/api/history", methods=["DELETE"])
def api_history_clear():
    storage.clear_history()
    return jsonify({"ok": True})


# ------------------------------------------------------------------------ Alerts --

@app.route("/api/alerts", methods=["GET"])
def api_alerts_list():
    settings = storage.get_settings()
    if not settings["alerts_enabled"]:
        return jsonify([])
    return jsonify(storage.list_alerts())


@app.route("/api/alerts/ack", methods=["POST"])
def api_alerts_ack():
    body = request.get_json(silent=True) or {}
    key = body.get("key")
    if not key:
        return jsonify({"error": "Missing key"}), 400
    storage.acknowledge_alert(key)
    return jsonify({"ok": True})


# ---------------------------------------------------------------------- Settings --

@app.route("/api/settings", methods=["GET"])
def api_settings_get():
    return jsonify(storage.get_public_settings())


@app.route("/api/settings", methods=["POST"])
def api_settings_post():
    body = request.get_json(silent=True) or {}
    try:
        storage.update_settings(body)
    except ValueError as err:
        return jsonify({"error": str(err)}), 400
    return jsonify(storage.get_public_settings())


# ------------------------------------------------------------------------- About --

@app.route("/api/about", methods=["GET"])
def api_about():
    return jsonify(storage.get_about_stats())


# ------------------------------------------------------------------------- Email --

def _build_report_email(record):
    lines = []
    lines.append("SIEM LITE - ANALYSIS REPORT")
    lines.append("File: " + record.get("filename", "unknown"))
    lines.append("Scanned: " + record.get("uploadedAt", "unknown"))
    lines.append("")
    lines.append("Threat Score: " + str(record.get("threatScore", 0)) + "%")
    lines.append("Failed Logins: " + str(record.get("failedLogins", 0)))
    lines.append("Suspicious IPs: " + str(record.get("suspiciousIps", 0)))
    lines.append("Critical Events: " + str(record.get("criticalEvents", 0)))
    lines.append("Total Events Processed: " + str(record.get("totalEvents", 0)))
    lines.append("")
    lines.append("EVENTS BY SEVERITY")
    for s in record.get("severity", []):
        lines.append("  " + str(s.get("name")) + ": " + str(s.get("value")))
    lines.append("")
    lines.append("TOP SUSPICIOUS IPs")
    for r in record.get("suspiciousIpRows", []):
        lines.append(
            "  " + r.get("ip", "") + " (" + r.get("country", "Unknown") + ") - " +
            str(r.get("risk", "")).upper() + " - " + str(r.get("events", 0)) +
            " events - last seen " + r.get("seen", "")
        )
    lines.append("")
    lines.append("RECENT CRITICAL EVENTS")
    for r in record.get("criticalEventRows", []):
        lines.append("  [" + r.get("time", "") + "] " + r.get("title", ""))
    return "\n".join(lines)


@app.route("/api/email/test", methods=["POST"])
def api_email_test():
    settings = storage.get_settings()
    body = "This is a test email from SIEM Lite \u2014 your mail settings are working.\n\nSent " + \
           datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        mailer.send_email(settings.get("alert_email"), "SIEM Lite - Test Email", body)
    except ValueError as err:
        return jsonify({"error": str(err)}), 400
    return jsonify({"ok": True})


@app.route("/api/email/send", methods=["POST"])
def api_email_send():
    body_in = request.get_json(silent=True) or {}
    scan_id = body_in.get("scanId")

    if scan_id:
        record = storage.get_scan(scan_id)
        if not record:
            return jsonify({"error": "Scan not found"}), 404
    else:
        history = storage.list_history(limit=1)
        if not history:
            return jsonify({"error": "No scans to email yet — run one first."}), 400
        record = storage.get_scan(history[0]["id"])

    settings = storage.get_settings()
    subject = "SIEM Lite Report - " + record.get("filename", "scan") + \
              " (" + str(record.get("threatScore", 0)) + "% risk)"
    body = _build_report_email(record)

    try:
        mailer.send_email(settings.get("alert_email"), subject, body)
    except ValueError as err:
        return jsonify({"error": str(err)}), 400
    return jsonify({"ok": True})


@app.route("/api/email/status", methods=["GET"])
def api_email_status():
    return jsonify({"configured": mailer.is_configured()})


if __name__ == "__main__":
    app.run(debug=True, port=5001)
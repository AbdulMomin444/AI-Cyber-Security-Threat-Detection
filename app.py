from flask import Flask, render_template, jsonify, request, send_file
import csv
import io
import os
from collections import Counter

app = Flask(__name__)

LOG_FILE = "anomaly_log.csv"


# ============================
# LOAD LOGS
# ============================
def load_logs():
    logs = []

    try:
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, "r", encoding="utf-8") as file:
                reader = csv.reader(file)
                next(reader, None)
                logs = list(reader)

    except Exception as e:
        print("Error loading logs:", e)

    return logs


# ============================
# HOME
# ============================
@app.route("/")
def index():
    return render_template("index.html")


# ============================
# LIVE LOGS API
# ============================
@app.route("/logs")
def get_logs():
    logs = load_logs()

    search = request.args.get("search", "").lower()
    status = request.args.get("status", "")
    attack = request.args.get("attack", "")

    filtered_logs = []

    for log in logs:
        row_text = " ".join(log).lower()

        if search and search not in row_text:
            continue

        if status and len(log) > 5 and log[5] != status:
            continue

        if attack and len(log) > 6 and log[6] != attack:
            continue

        filtered_logs.append(log)

    return jsonify(filtered_logs[-50:])


# ============================
# ANALYTICS API
# ============================
@app.route("/analytics")
def analytics():
    logs = load_logs()

    attack_counts = Counter()
    anomaly_count = 0
    blocked_count = 0
    unique_sources = set()

    for log in logs:
        try:
            if len(log) >= 10:
                unique_sources.add(log[1])

                attack_counts[log[6]] += 1

                if log[5] == "Anomaly":
                    anomaly_count += 1

                if "Critical" in log[7]:
                    blocked_count += 1

        except:
            continue

    return jsonify({
        "total_logs": len(logs),
        "anomalies": anomaly_count,
        "normal": len(logs) - anomaly_count,
        "blocked": blocked_count,
        "sources": len(unique_sources),
        "attack_labels": list(attack_counts.keys()),
        "attack_values": list(attack_counts.values())
    })


# ============================
# EXPORT CSV
# ============================
@app.route("/export")
def export_logs():
    logs = load_logs()

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "Timestamp", "Source IP", "Destination IP",
        "Protocol", "Length", "Status",
        "Attack Type", "Threat Level",
        "Explanation", "Location"
    ])

    writer.writerows(logs)

    memory_file = io.BytesIO()
    memory_file.write(output.getvalue().encode("utf-8"))
    memory_file.seek(0)

    return send_file(
        memory_file,
        mimetype="text/csv",
        as_attachment=True,
        download_name="cyber_security_logs.csv"
    )


# ============================
# RUN
# ============================
if __name__ == "__main__":
    app.run(debug=True)
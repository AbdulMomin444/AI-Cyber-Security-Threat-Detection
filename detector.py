import joblib
from scapy.all import sniff
from scapy.layers.inet import IP
import time
import csv
from datetime import datetime
import os
import smtplib
from email.mime.text import MIMEText
from collections import defaultdict
import subprocess
import pandas as pd
import requests

# ==============================
# EXPLANATION FUNCTION
# ==============================
def explain_attack(attack_type, protocol, length):
    if attack_type == "DDoS":
        return "High traffic from a single IP detected (DDoS)."
    elif attack_type == "Port Scan":
        return "Multiple ports detected from same IP."
    elif protocol == 6 and length > 1000:
        return "Large TCP packet (suspicious transfer)."
    elif protocol == 17:
        return "UDP traffic (possible amplification attack)."
    else:
        return "Normal behavior"

# ==============================
# THREAT LEVEL
# ==============================
def get_threat_level(attack_type):
    if attack_type == "DDoS":
        return "Critical"
    elif attack_type == "Port Scan":
        return "High"
    else:
        return "Low"

# ==============================
# TRACKING
# ==============================
packet_count = defaultdict(int)
port_scan = defaultdict(set)
alerted_ips = set()
blocked_ips = set()

# ==============================
# EMAIL CONFIG
# ==============================
sender_email = os.getenv("EMAIL_USER")
app_password = os.getenv("EMAIL_PASSWORD")
receiver_email = os.getenv("EMAIL_USER")

print("\n========== EMAIL DEBUG ==========")
print("Sender Email:", sender_email)
print("Receiver Email:", receiver_email)

if app_password:
    print("App Password Loaded Successfully ✅")
else:
    print("❌ App Password NOT Loaded")

print("=================================\n")

# ==============================
# EMAIL FUNCTION
# ==============================
def send_email_alert(src_ip, dst_ip, protocol, length, attack_type, threat, location):

    if src_ip in alerted_ips:
        return

    if not sender_email or not app_password:
        print("❌ Email credentials missing.")
        return

    subject = "🚨 AI Cyber Alert - Threat Detected"

    body = f"""
🚨 ALERT DETECTED 🚨

Attack Type: {attack_type}
Threat Level: {threat}

Source IP: {src_ip}
Destination IP: {dst_ip}

Protocol: {protocol}
Packet Length: {length}

Location: {location}

Detection Time: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
"""

    try:
        msg = MIMEText(body, "plain", "utf-8")

        msg["Subject"] = subject
        msg["From"] = sender_email
        msg["To"] = receiver_email

        print("📡 Connecting Gmail SMTP...")

        server = smtplib.SMTP("smtp.gmail.com", 587)

        server.ehlo()
        server.starttls()
        server.ehlo()

        print("🔐 Logging into Gmail...")

        server.login(sender_email, app_password)

        print("📨 Sending Email...")

        server.sendmail(
            sender_email,
            receiver_email,
            msg.as_string()
        )

        server.quit()

        alerted_ips.add(src_ip)

        print("✅ EMAIL ALERT SENT SUCCESSFULLY!")

    except Exception as e:
        print("❌ EMAIL ERROR:")
        print(e)
# ==============================
# BLOCK IP FUNCTION
# ==============================
def block_ip(ip):
    if ip in blocked_ips:
        return

    try:
        command = f'netsh advfirewall firewall add rule name="Block {ip}" dir=in action=block remoteip={ip}'
        subprocess.run(command, shell=True)

        blocked_ips.add(ip)
        print(f"⛔ IP BLOCKED: {ip}")

    except Exception as e:
        print("Blocking Error:", e)

# ==============================
# GEO LOCATION
# ==============================
geo_cache = {}

def get_ip_location(ip):
    if ip.startswith("192.168"):
        return "Local Network"

    if ip in geo_cache:
        return geo_cache[ip]

    try:
        res = requests.get(f"http://ip-api.com/json/{ip}", timeout=2).json()

        if res["status"] == "success":
            location = f"{res.get('country')}, {res.get('city')} ({res.get('isp')})"
        else:
            location = "Unknown"

        geo_cache[ip] = location
        return location
    except:
        return "Unknown"

# ==============================
# LOAD MODEL
# ==============================
model = joblib.load("Notebooks/model.pkl")

# ==============================
# CSV FILE
# ==============================
log_file = "anomaly_log.csv"

if not os.path.exists(log_file):
    with open(log_file, "w", newline='') as f:
        writer = csv.writer(f)
        writer.writerow([
            "Timestamp", "Source IP", "Destination IP",
            "Protocol", "Length", "Status",
            "Attack Type", "Threat Level",
            "Explanation", "Location"
        ])

# ==============================
# PACKET PROCESSING
# ==============================
def process_packet(packet):
    if IP in packet:
        try:
            length = len(packet)
            protocol = packet[IP].proto
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            location = get_ip_location(src_ip)

            packet_count[src_ip] += 1
            port_scan[src_ip].add(protocol)

            data = pd.DataFrame([[packet.time, protocol, length]],
                                columns=["Time", "Protocol", "Length"])

            prediction = model.predict(data)

            attack_type = "Normal"

            if packet_count[src_ip] > 50:
                attack_type = "DDoS"
            elif len(port_scan[src_ip]) > 10:
                attack_type = "Port Scan"

            if prediction[0] == -1 or attack_type != "Normal":
                status = "Anomaly"
            else:
                status = "Normal"

            explanation = explain_attack(attack_type, protocol, length)
            threat = get_threat_level(attack_type)

            print(f"{status}: {src_ip} → {dst_ip} | {threat}")

            # 🔥 EMAIL + BLOCK ONLY ON REAL ATTACK
            if status == "Anomaly" and attack_type != "Normal":
                send_email_alert(src_ip, dst_ip, protocol, length, attack_type, threat, location)
                block_ip(src_ip)

            # SAVE CSV
            with open(log_file, "a", newline='') as f:
                writer = csv.writer(f)
                current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                writer.writerow([
                    current_time, src_ip, dst_ip,
                    protocol, length, status,
                    attack_type, threat,
                    explanation, location
                ])

        except Exception as e:
            print("Error:", e)

print("🚀 Monitoring Started...")
time.sleep(1)

sniff(filter="ip", prn=process_packet, store=False)
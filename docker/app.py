"""
larkspur_automation — Wazuh alert webhook and automated remediation stack
CA1 Assessment — B9CY110 Communication and Network Security
Samuel Ogunlusi | 20086108 | DBS MSc Cybersecurity
"""
import subprocess, datetime, json
from flask import Flask, request, jsonify

app = Flask(__name__)
audit_trail = []

ALLOWLIST = {
    "block_ip":    lambda d: ["iptables", "-I", "INPUT", "-s", d["srcip"], "-j", "DROP"],
    "unblock_ip":  lambda d: ["iptables", "-D", "INPUT", "-s", d["target"], "-j", "DROP"],
    "lock_user":   lambda d: ["passwd", "-L", d["srcuser"]],
    "unlock_user": lambda d: ["passwd", "-U", d["user"]],
}

def classify(alert):
    rule_id = alert.get("rule", {}).get("id", "")
    level   = int(alert.get("rule", {}).get("level", 0))
    if rule_id in ("100002",) or level >= 10:
        return "block_ip", "HIGH"
    if rule_id in ("100005",):
        return "lock_user", "MEDIUM"
    return "no_action", "LOW"

def verify(action, data):
    if action == "block_ip":
        result = subprocess.run(["iptables","-L","INPUT","-n"], capture_output=True, text=True)
        return data.get("srcip","") in result.stdout
    if action == "lock_user":
        result = subprocess.run(["passwd","-S", data.get("srcuser","")], capture_output=True, text=True)
        return " L " in result.stdout
    return True

@app.route("/webhook", methods=["POST"])
def webhook():
    alert  = request.json
    action, severity = classify(alert)
    data   = alert.get("data", {})
    record = {
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "agent":     alert.get("agent", {}).get("name", "unknown"),
        "rule_id":   alert.get("rule", {}).get("id", ""),
        "action":    action,
        "severity":  severity,
        "data":      data,
        "status":    "no_action",
        "verified":  False,
    }
    if action in ALLOWLIST:
        try:
            cmd = ALLOWLIST[action](data)
            subprocess.run(cmd, check=True)
            record["status"]   = "executed"
            record["verified"] = verify(action, data)
        except Exception as e:
            record["status"] = f"error: {e}"
    audit_trail.append(record)
    return jsonify(record), 200

@app.route("/audit", methods=["GET"])
def audit():
    return jsonify(audit_trail), 200

@app.route("/rollback", methods=["POST"])
def rollback():
    body = request.json or {}
    action = body.get("action", "")
    target = body.get("target", body.get("user", ""))
    if not action or not target:
        return jsonify({"status": "error", "reason": "action and target required"}), 400
    if action not in ALLOWLIST:
        return jsonify({"status": "error", "reason": "action not in allowlist"}), 400
    try:
        cmd = ALLOWLIST[action]({"target": target, "user": target, "srcip": target, "srcuser": target})
        subprocess.run(cmd, check=True)
        return jsonify({"status": "success", "action": action, "target": target}), 200
    except Exception as e:
        return jsonify({"status": "error", "reason": str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)

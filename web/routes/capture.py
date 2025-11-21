from flask import Blueprint, jsonify
from ghostrelay.responder_manager import ResponderManager
import os
import re

capture_bp = Blueprint("capture", __name__)
RESP = ResponderManager()

# -------------------------------
# Start Responder capture
# -------------------------------
@capture_bp.route("/start", methods=["POST"])
def start_capture():
    try:
        RESP.start_capture_mode()
        return jsonify({"status": "started"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# -------------------------------
# Stop Responder
# -------------------------------
@capture_bp.route("/stop", methods=["POST"])
def stop_capture():
    try:
        RESP.stop_responder()
        return jsonify({"status": "stopped"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# -------------------------------
# Return running state
# -------------------------------
@capture_bp.route("/status")
def status():
    return jsonify({
        "running": RESP.running
    })


# -------------------------------
# Return latest log lines
# -------------------------------
@capture_bp.route("/logs")
def logs():
    try:
        # Our log lives inside ghostrelay/
        base = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        log_file = os.path.join(base, "ghostrelay.log")

        if not os.path.exists(log_file):
            return "Log error: log file not found", 500

        with open(log_file, "r", errors="ignore") as f:
            data = f.read()[-12000:]  # last 12KB

        clean = re.sub(r"\x1B\[[0-9;]*[A-Za-z]", "", data)
        return clean, 200, {"Content-Type": "text/plain"}

    except Exception as e:
        return f"Log error: {e}", 500


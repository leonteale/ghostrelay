from flask import Blueprint, jsonify, render_template
from ghostrelay.sessions import SESSION_STORE
import re

sessions_bp = Blueprint("sessions", __name__)

ANSI_RE = re.compile(r"\x1B\[[0-9;]*[A-Za-z]")

# ---------------------------------
# Legacy page view (not dashboard)
# ---------------------------------
@sessions_bp.route("/")
def list_sessions_page():
    sessions = SESSION_STORE.list_sessions()
    return render_template("sessions.html", sessions=sessions)


# ---------------------------------
# JSON API for Dashboard
# ---------------------------------
@sessions_bp.route("/api")
def list_sessions_api():
    out = []
    for s in SESSION_STORE.list_sessions():
        out.append({
            "id": s.id,
            "created_at": s.created_at,
            "source_ip": s.source_ip,
            "dest_ip": s.dest_ip,
            "direction": s.direction,
            "username": s.username,
            "domain": s.domain,
            "message_type": s.message_type_name,
            "hash_type": s.hash_type,
        })
    return jsonify(out)


# ---------------------------------
# Clear all sessions
# ---------------------------------
@sessions_bp.route("/clear", methods=["POST"])
def clear_sessions():
    SESSION_STORE.clear()
    return jsonify({"status": "cleared"})


# ---------------------------------
# Export captured hashes
# (cleaned, ANSI stripped)
# ---------------------------------
@sessions_bp.route("/hashes")
def hashes_export():
    lines = []

    for s in SESSION_STORE.list_sessions():
        try:
            raw = s.raw_data.decode(errors="ignore").strip()
            clean = ANSI_RE.sub("", raw)

            if clean:
                lines.append(clean)

        except Exception:
            continue

    output = "\n".join(lines)
    return output, 200, {"Content-Type": "text/plain"}


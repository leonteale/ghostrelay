from flask import Blueprint, jsonify, render_template
from ghostrelay.sessions import SESSION_STORE
import re
import os

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
# JSON API used by dashboard
# ---------------------------------
@sessions_bp.route("/api")
def list_sessions_api():
    out = []
    for s in SESSION_STORE.list_sessions():
        out.append(
            {
                "id": s.id,
                "created_at": s.created_at,
                "source_ip": s.source_ip,
                "dest_ip": s.dest_ip,
                "direction": s.direction,
                "username": s.username,
                "domain": s.domain,
                "message_type": s.message_type_name,
                "hash_type": s.hash_type,
            }
        )
    return jsonify(out)


# ---------------------------------
# Clear all sessions + responder log
# ---------------------------------
@sessions_bp.route("/clear", methods=["POST"])
def clear_sessions():
    # Clear in-memory + persistent session store
    SESSION_STORE.clear()

    # Also truncate ghostrelay.log so a new run starts visually clean
    try:
        # This file lives in ghostrelay/web/routes/
        # Go up to ghostrelay/ and point at ghostrelay.log
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
        log_path = os.path.join(base_dir, "ghostrelay.log")

        if os.path.exists(log_path):
            # Truncate in place
            with open(log_path, "w", encoding="utf8"):
                pass
    except Exception:
        # Best-effort only – do not break the API if log clearing fails
        pass

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


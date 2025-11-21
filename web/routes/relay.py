from flask import Blueprint, request, jsonify
from ghostrelay.relay_smb import SMBRelayTarget, relay_ntlm_to_target
from ghostrelay.sessions import SESSION_STORE

relay_bp = Blueprint("relay", __name__)


@relay_bp.route("/", methods=["POST"])
def do_relay():
    """
    Trigger a DRY-RUN relay operation.
    """
    data = request.get_json(force=True)

    session_id = int(data.get("session_id", -1))
    host = data.get("host")

    if session_id < 0 or not host:
        return jsonify({"error": "Missing session_id or host"}), 400

    if not SESSION_STORE.get_session(session_id):
        return jsonify({"error": "Invalid session ID"}), 404

    target = SMBRelayTarget(host)
    relay_ntlm_to_target(session_id, target)

    return jsonify({"status": "ok"})


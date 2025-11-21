from flask import Blueprint, request, jsonify, render_template
from ghostrelay.relay_smb import list_relayable_targets

targets_bp = Blueprint("targets", __name__)

@targets_bp.route("/", methods=["GET"])
def targets_index():
    """
    Render the SMB target scanning UI.
    """
    return render_template("targets.html")

@targets_bp.route("/scan", methods=["POST"])
def scan_targets():
    """
    Accept a JSON list of hosts and return SMB signing status.
    """
    hosts = request.json.get("hosts", [])
    results = list_relayable_targets(hosts)

    return jsonify([
        {"host": t.host, "signing_required": t.signing_required}
        for t in results
    ])


# relay_smb.py

from __future__ import annotations
from typing import List, Optional, Dict

from impacket.smbconnection import SMBConnection
from ghostrelay.sessions import SESSION_STORE, NTLMSession


class SMBRelayTarget:
    def __init__(self, host: str, port: int = 445):
        self.host = host
        self.port = port
        # None = unknown, True = signing required, False = signing not required
        self.signing_required: Optional[bool] = None

    def __repr__(self):
        s = "UNKNOWN"
        if self.signing_required is True:
            s = "REQUIRED"
        elif self.signing_required is False:
            s = "DISABLED"
        return f"<SMBRelayTarget {self.host}:{self.port} signing={s}>"


def check_smb_signing(target: SMBRelayTarget) -> SMBRelayTarget:
    """
    SMB signing detection using Impacket's negotiated flags.

    Logic:
    - Negotiate an SMB session (no auth needed)
    - Ask the underlying SMBServer object whether signing is required
      via is_signing_required() or RequireMessageSigning.
    """

    try:
        conn = SMBConnection(
            remoteName=target.host,
            remoteHost=target.host,
            sess_port=target.port,
            timeout=3,
        )

        # Negotiate SMB session; some versions negotiate lazily
        try:
            conn.negotiateSession()
        except Exception:
            # If negotiateSession raises but connection is valid, Impacket
            # may still have populated the SMBServer object internally.
            pass

        try:
            srv = conn.getSMBServer()
        except Exception as e:
            print(f"[GhostRelay][SMB] {target.host}: failed to get SMBServer ({e})")
            target.signing_required = None
            try:
                conn.close()
            except Exception:
                pass
            return target

        signing_required = None

        # Prefer the explicit helper if available
        try:
            if hasattr(srv, "is_signing_required"):
                signing_required = bool(srv.is_signing_required())
            elif hasattr(srv, "RequireMessageSigning"):
                signing_required = bool(getattr(srv, "RequireMessageSigning"))
        except Exception as e:
            print(f"[GhostRelay][SMB] {target.host}: failed to read signing flag ({e})")
            signing_required = None

        if signing_required is True:
            target.signing_required = True
            print(f"[GhostRelay][SMB] {target.host}: Signing REQUIRED.")
        elif signing_required is False:
            target.signing_required = False
            print(f"[GhostRelay][SMB] {target.host}: Signing NOT required.")
        else:
            target.signing_required = None
            print(f"[GhostRelay][SMB] {target.host}: Signing UNKNOWN.")

        try:
            conn.close()
        except Exception:
            pass

        return target

    except Exception as e:
        print(f"[GhostRelay][SMB] {target.host}: SMB connection failed ({e})")
        target.signing_required = None
        return target


def list_relayable_targets(hosts: List[str]) -> List[SMBRelayTarget]:
    """
    For a list of host strings, return targets where signing is disabled.
    """
    results: List[SMBRelayTarget] = []

    for h in hosts:
        t = SMBRelayTarget(h)
        t = check_smb_signing(t)

        if t.signing_required is False:
            print(f"[GhostRelay][SMB] {h}: SMB signing DISABLED – relay possible.")
            results.append(t)
        elif t.signing_required is True:
            print(f"[GhostRelay][SMB] {h}: SMB signing REQUIRED – relay blocked.")
        else:
            print(f"[GhostRelay][SMB] {h}: Signing UNKNOWN – skipping for now.")

    return results


def parse_netntlmv2_hash(hash_line: str) -> Dict[str, Optional[str]]:
    """
    Parse a Responder-style NetNTLMv2 line, e.g.:

      username::DOMAIN:server_chal:ntlm_response:blob...

    Returns a dict with components. If parsing fails, fields may be None.
    """
    result: Dict[str, Optional[str]] = {
        "username": None,
        "domain": None,
        "server_challenge": None,
        "response": None,
        "blob": None,
    }

    line = hash_line.strip()
    parts = line.split(":")

    # NetNTLMv2 basic shape:
    #   0: username
    #   1: (often empty, hence username::DOMAIN:...)
    #   2: domain
    #   3: server_challenge
    #   4: ntlm_response
    #   5: blob (rest)
    if len(parts) < 5:
        return result

    result["username"] = parts[0] or None

    if parts[1] == "":
        # username::DOMAIN:...
        result["domain"] = parts[2] or None
        base_idx = 3
    else:
        # Fallback: username:DOMAIN:...
        result["domain"] = parts[1] or None
        base_idx = 2

    if len(parts) > base_idx:
        result["server_challenge"] = parts[base_idx] or None
    if len(parts) > base_idx + 1:
        result["response"] = parts[base_idx + 1] or None
    if len(parts) > base_idx + 2:
        result["blob"] = ":".join(parts[base_idx + 2 :]) or None

    return result


def relay_ntlm_to_target(session_id: int, target: SMBRelayTarget):
    """
    SAFE VERSION (no real relay):

    - Fetch session by ID
    - Decode stored NTLM line
    - Parse NetNTLMv2 components (username, domain, etc.)
    - Print a clear summary of what WOULD be relayed

    The actual "use this NTLM to authenticate and run commands" part is left
    intentionally unimplemented.
    """
    s: NTLMSession | None = SESSION_STORE.get_session(session_id)
    if not s:
        print(f"[GhostRelay][SMB] No session {session_id} found.")
        return

    try:
        hash_line = s.raw_data.decode(errors="ignore").strip()
    except Exception as e:
        print(f"[GhostRelay][SMB] Session {session_id}: failed to decode raw data ({e})")
        return

    meta = parse_netntlmv2_hash(hash_line)

    print("\n[GhostRelay][SMB] === DRY-RUN NTLM RELAY SUMMARY ===")
    print(f"Session ID       : {s.id}")
    print(f"Source IP        : {s.source_ip}")
    print(f"Direction        : {s.direction}")
    print(f"Note             : {s.note}")
    print(f"Target           : {target.host}:{target.port}")
    print("")
    print("Parsed NetNTLMv2")
    print("----------------")
    print(f"Username         : {meta.get('username')}")
    print(f"Domain           : {meta.get('domain')}")
    print(f"Server challenge : {meta.get('server_challenge')}")
    print(f"Response (len)   : {len(meta.get('response') or '')} hex chars")
    print(f"Blob (present)   : {'yes' if meta.get('blob') else 'no'}")
    print("")
    print("Raw hash line:")
    print(hash_line)
    print("")
    print("[GhostRelay][SMB] DRY RUN ONLY – no network relay performed here.")
    print("                     This is where you would plug in your own")
    print("                     Impacket-based relay logic locally.")
    print("=============================================================\n")

    return


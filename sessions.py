# sessions.py  (persistent version)

from __future__ import annotations
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Any
import time
import threading
import json
import os

NTLM_MAGIC = b"NTLMSSP\x00"

# Always store sessions.json next to this file (inside ghostrelay/)
SESS_FILE = os.path.join(os.path.dirname(__file__), "sessions.json")


@dataclass
class NTLMSession:
    id: int
    created_at: float
    source_ip: str
    dest_ip: str
    direction: str
    raw_data: bytes
    note: str = ""

    message_type: Optional[int] = None
    message_type_name: Optional[str] = None
    username: Optional[str] = None
    domain: Optional[str] = None
    workstation: Optional[str] = None
    hash_type: Optional[str] = None   # e.g. NetNTLMv2


class SessionStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._sessions: Dict[int, NTLMSession] = {}
        self._counter = 0
        self._load()

    def _load(self):
        if not os.path.exists(SESS_FILE):
            return

        try:
            with open(SESS_FILE, "r") as f:
                data = json.load(f)

            for sid, s in data.items():
                sid = int(sid)
                sess = NTLMSession(
                    id=sid,
                    created_at=s["created_at"],
                    source_ip=s["source_ip"],
                    dest_ip=s["dest_ip"],
                    direction=s["direction"],
                    raw_data=bytes.fromhex(s["raw_data"]),
                    note=s.get("note", ""),
                    message_type=s.get("message_type"),
                    message_type_name=s.get("message_type_name"),
                    username=s.get("username"),
                    domain=s.get("domain"),
                    workstation=s.get("workstation"),
                    hash_type=s.get("hash_type"),
                )
                self._sessions[sid] = sess
                self._counter = max(self._counter, sid)

        except Exception as e:
            print(f"[GhostRelay][Sessions] Failed to load sessions.json: {e}")

    def _save(self):
        data: Dict[str, Any] = {}
        for sid, sess in self._sessions.items():
            entry = asdict(sess)
            entry["raw_data"] = sess.raw_data.hex()
            data[str(sid)] = entry

        try:
            with open(SESS_FILE, "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"[GhostRelay][Sessions] Failed to save sessions.json: {e}")

    def add_session(
        self,
        source_ip: str,
        dest_ip: str,
        direction: str,
        raw_data: bytes,
        note: str = "",
    ) -> NTLMSession:

        meta = _parse_ntlm_metadata(raw_data)

        with self._lock:
            self._counter += 1
            session = NTLMSession(
                id=self._counter,
                created_at=time.time(),
                source_ip=source_ip,
                dest_ip=dest_ip,
                direction=direction,
                raw_data=raw_data,
                note=note,
                message_type=meta.get("message_type"),
                message_type_name=meta.get("message_type_name"),
                username=meta.get("username"),
                domain=meta.get("domain"),
                workstation=meta.get("workstation"),
                hash_type=meta.get("hash_type"),
            )
            self._sessions[self._counter] = session
            self._save()
            return session

    def list_sessions(self) -> List[NTLMSession]:
        with self._lock:
            return list(self._sessions.values())

    def get_session(self, sid: int) -> Optional[NTLMSession]:
        with self._lock:
            return self._sessions.get(sid)

    def clear(self) -> None:
        with self._lock:
            self._sessions.clear()
            self._counter = 0
            self._save()


SESSION_STORE = SessionStore()


def _parse_ntlm_metadata(raw: bytes) -> Dict[str, Any]:
    """
    Try to pull out useful info from what we stored in raw_data.

    For Responder captures, raw_data is typically a NetNTLMv2 line:
        username::DOMAIN:server_chal:response:blob

    For future use, we keep the old NTLMSSP parser as a fallback.
    """
    meta: Dict[str, Any] = {
        "message_type": None,
        "message_type_name": None,
        "username": None,
        "domain": None,
        "workstation": None,
        "hash_type": None,
    }

    # First try: treat as ASCII NetNTLMv2 line
    try:
        line = raw.decode(errors="ignore").strip()
    except Exception:
        line = ""

    if line and ":" in line:
        parts = line.split(":")
        if len(parts) >= 4:
            # NetNTLMv2 typical shapes:
            #   user::DOMAIN:...
            #   user:DOMAIN:...
            username = parts[0] or None
            if parts[1] == "":
                domain = parts[2] or None
            else:
                domain = parts[1] or None

            meta["username"] = username
            meta["domain"] = domain
            meta["hash_type"] = "NetNTLMv2"
            # Nothing else to do here, this is enough for the UI
            return meta

    # Fallback: if we ever store real binary NTLM messages, try to classify
    idx = raw.find(NTLM_MAGIC)
    if idx == -1:
        return meta

    if len(raw) < idx + 12:
        return meta

    msg_type = int.from_bytes(raw[idx + 8: idx + 12], "little")
    mapping = {1: "NEGOTIATE", 2: "CHALLENGE", 3: "AUTHENTICATE"}

    meta["message_type"] = msg_type
    meta["message_type_name"] = mapping.get(msg_type, f"UNKNOWN_{msg_type}")
    # no username/domain parsing for this fallback yet
    return meta


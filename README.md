# GhostRelay

GhostRelay is a lightweight web-based automation layer designed to streamline internal penetration testing workflows involving Responder and MultiRelay.  
It provides a modern UI, automated parsing, credential extraction, and relay tooling in a single integrated platform.

GhostRelay is intended for red-team operators and penetration testers who need a fast, simple, reliable interface for capturing and relaying NTLM authentication traffic on internal networks.

## Features
- Start/stop Responder from the UI
- Live ANSI-cleaned logs
- Automatic extraction of usernames, domains, hashes, source IPs, and services
- Relay buttons for NetNTLMv2 sessions
- Hash export in Hashcat format
- Planned: MultiRelay automation, SMB signing scanner, network discovery, Hashcat helper, Debian package, systemd services

## Project Structure
ghostrelay/
├── ghostrelay.py
├── config.py
├── responder_manager.py
├── relay_smb.py
├── sessions.py
├── routes/
├── templates/
├── web/
└── run_webui.sh

## Running
pip3 install -r requirements.txt
./run_webui.sh

## URL
http://127.0.0.1:5000

## Legal Notice
GhostRelay is for authorised penetration testing only. Misuse is illegal.

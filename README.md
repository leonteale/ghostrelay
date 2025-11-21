# GhostRelay

GhostRelay is a lightweight, offensive security tool providing a modern web interface for **Responder**, **NetNTLMv2 hash capture**, and **relay automation**.  
It is designed for **internal penetration testers**, giving you a clean dashboard, real-time logs, session parsing, and relay execution with one click.

---

## 🚀 Features

### ✔ Responder Automation  
- Start and stop Responder from a single button  
- Auto-cleaning of ANSI escape sequences  
- Live real-time log streaming to the dashboard  
- Automatic parsing of:
  - Client IP  
  - Queried resource  
  - Username  
  - Domain  
  - Hash type (NetNTLMv2)

### ✔ Session Tracking  
- Every captured authentication attempt is stored  
- View all sessions in a sortable table  
- One-click relay for compatible NetNTLMv2 sessions  
- Clear all saved sessions instantly  

### ✔ Hash Export  
- Export all parsed hashes in **Hashcat-ready format**  
- Copy-to-clipboard support  

### ✔ Planned Features  
- MultiRelay automation (+ log integration)  
- SMB signing scanner  
- Network discovery module  
- Hashcat automation helper  
- Debian installer + Systemd service files  
- API token authentication for safer deployments  

---

## 📁 Project Structure

```
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
```

---

## 🧱 Technology Stack

- **Python 3**
- **Flask** (Web UI backend)
- **Responder** (external tool)
- **WebSockets / SSE** (live logs)
- **TailwindCSS** (UI styling)
- **Vanilla JavaScript** (dashboard logic)

---

## ▶️ Running GhostRelay

### 1. Install Dependencies  
```
pip3 install -r requirements.txt
```

### 2. Start Web UI  
```
./run_webui.sh
```

### 3. Access the Dashboard  
Open your browser and visit:

```
http://127.0.0.1:5000
```

---

## ⚠️ Legal Warning

GhostRelay is an offensive security tool.  
Do **NOT** use this software without explicit written permission.  
You are responsible for how you use it.

---

## 🛠 Author

Created by **Leon Teale**  
https://pentest.training/
https://github.com/leonteale

---



# config.py

from dataclasses import dataclass, field


@dataclass
class ResponderConfig:
    base_dir: str = "/usr/share/responder"
    tools_dir: str = "/usr/share/responder/tools"
    db_path: str = "/usr/share/responder/Responder.db"
    multirelay_path: str = "/usr/share/responder/tools/MultiRelay.py"


@dataclass
class GhostRelayConfig:
    listen_host: str = "127.0.0.1"
    listen_port: int = 1080
    log_ntlm: bool = True
    log_file: str | None = "ghostrelay.log"

    # Python 3.13 requires default_factory for nested dataclasses
    responder: ResponderConfig = field(default_factory=ResponderConfig)


CONFIG = GhostRelayConfig()


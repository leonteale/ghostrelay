# socks_proxy.py

from __future__ import annotations
import socket
import threading
import struct
import logging
from typing import Tuple

from sessions import SESSION_STORE

NTLM_MAGIC = b"NTLMSSP\x00"


class GhostRelaySocksServer:
    def __init__(self, host: str, port: int, logger: logging.Logger) -> None:
        self.host = host
        self.port = port
        self.logger = logger
        self._server_sock = None
        self._running = False

    def start(self) -> None:
        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.bind((self.host, self.port))
        self._server_sock.listen(200)
        self._running = True
        self.logger.info(f"[GhostRelay] SOCKS5 listening on {self.host}:{self.port}")

        try:
            while self._running:
                client_sock, addr = self._server_sock.accept()
                t = threading.Thread(
                    target=self._handle_client,
                    args=(client_sock, addr),
                    daemon=True,
                )
                t.start()
        finally:
            self.stop()

    def stop(self) -> None:
        self._running = False
        if self._server_sock:
            self._server_sock.close()
            self._server_sock = None

    def _handle_client(self, client_sock: socket.socket, addr: Tuple[str, int]) -> None:
        try:
            self._socks5_handshake(client_sock)
            dest_host, dest_port = self._socks5_connect_request(client_sock)
            self.logger.info(
                f"[GhostRelay] CONNECT {addr[0]}:{addr[1]} → {dest_host}:{dest_port}"
            )

            remote_sock = socket.create_connection((dest_host, dest_port), timeout=10)
            self._send_socks5_reply(client_sock, 0x00, remote_sock.getsockname())

            self._relay(client_sock, remote_sock, addr, (dest_host, dest_port))

        except Exception as e:
            self.logger.debug(f"[GhostRelay] Error: {e}")
        finally:
            try:
                client_sock.close()
            except:
                pass

    def _socks5_handshake(self, client_sock: socket.socket) -> None:
        data = client_sock.recv(2)
        ver, nmethods = data[0], data[1]

        methods = client_sock.recv(nmethods)
        if 0x00 not in methods:
            client_sock.sendall(b"\x05\xff")
            raise RuntimeError("NO AUTH unsupported")

        client_sock.sendall(b"\x05\x00")

    def _socks5_connect_request(self, client_sock: socket.socket) -> Tuple[str, int]:
        header = client_sock.recv(4)
        ver, cmd, _, atyp = header

        if cmd != 0x01:
            raise RuntimeError("Only CONNECT supported")

        if atyp == 0x01:
            addr = socket.inet_ntoa(client_sock.recv(4))
        elif atyp == 0x03:
            ln = client_sock.recv(1)[0]
            addr = client_sock.recv(ln).decode()
        elif atyp == 0x04:
            addr = socket.inet_ntop(socket.AF_INET6, client_sock.recv(16))
        else:
            raise RuntimeError("Bad ATYP")

        port = struct.unpack("!H", client_sock.recv(2))[0]
        return addr, port

    def _send_socks5_reply(self, client_sock, rep, bind_addr):
        client_sock._


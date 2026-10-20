#!/usr/bin/env python3
"""Minimal SPR plugin API over its Unix socket."""

import fcntl
import json
import os
import socket
import socketserver
import struct
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlsplit

SOCKET_PATH = Path(os.environ.get("SPR_KRUN_PLUGIN_SOCKET", "/state/plugins/spr-mitm-tester/socket.sock"))
RUN_DIR = Path("/run/mitm-tester")
EVENTS = Path("/state/plugins/spr-mitm-tester/events.jsonl")
UI = Path("/ui")
INTERFACE = "mitmtst0"


def container_ip():
    name = os.environ.get("AUDIT_INTERFACE", "eth0")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            raw = fcntl.ioctl(sock.fileno(), 0x8915, struct.pack("256s", name.encode()[:15]))
        return socket.inet_ntoa(raw[20:24])
    except OSError:
        return ""


def proxy_ready():
    if not (RUN_DIR / "authority.json").exists():
        return False
    try:
        with socket.create_connection(("127.0.0.1", 9999), timeout=0.2):
            return True
    except OSError:
        return False


def read_events():
    if not EVENTS.exists():
        return []
    with EVENTS.open("rb") as source:
        source.seek(max(0, EVENTS.stat().st_size - 400_000))
        if source.tell():
            source.readline()
        lines = source.readlines()[-300:]
    result = []
    for line in lines:
        try:
            result.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return result


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def respond_json(self, value):
        payload = json.dumps(value).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        route = urlsplit(self.path).path
        if route == "/status":
            authority_path = RUN_DIR / "authority.json"
            authority = json.loads(authority_path.read_text()) if authority_path.exists() else None
            return self.respond_json({"ready": proxy_ready(), "authority": authority})
        if route == "/events":
            return self.respond_json(read_events())
        if route == "/topology":
            ip = container_ip()
            return self.respond_json({
                "Nodes": [{"ID": "root", "Kind": "root", "Name": "SPR", "ConnType": "wired", "Online": True}],
                "Edges": [],
                "Sinks": [{"ID": "mitm-tester", "Name": "MITM tester", "Iface": INTERFACE,
                           "IP": ip, "Online": bool(ip) and proxy_ready()}],
            })
        candidate = (UI / (route.lstrip("/") or "index.html")).resolve()
        if not candidate.is_relative_to(UI) or not candidate.is_file():
            candidate = UI / "index.html"
        try:
            content = candidate.read_bytes()
        except OSError:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html" if candidate.suffix == ".html" else "application/octet-stream")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)


class UnixHTTPServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


if __name__ == "__main__":
    SOCKET_PATH.parent.mkdir(parents=True, exist_ok=True)
    SOCKET_PATH.unlink(missing_ok=True)
    with UnixHTTPServer(str(SOCKET_PATH), Handler) as server:
        os.chmod(SOCKET_PATH, 0o660)
        server.serve_forever()

#!/usr/bin/env python3
"""Minimal SPR plugin API over its Unix socket."""

import fcntl
import json
import os
import socket
import socketserver
import struct
import tempfile
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlsplit

from configure_upstream_tls import STATE_CONFIG, configured_settings
from emudhra_authority import authority_details

SOCKET_PATH = Path(os.environ.get("SPR_KRUN_PLUGIN_SOCKET", "/state/plugins/spr-mitm-tester/socket.sock"))
RUN_DIR = Path("/run/mitm-tester")
EVENTS = Path("/state/plugins/spr-mitm-tester/events.jsonl")
WEB_TOKEN = Path("/state/plugins/spr-mitm-tester/mitmweb-token")
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
    return port_listening(9999)


def web_ready():
    return port_listening(8081)


def port_listening(port):
    # A synthetic connection to the transparent listener has no original
    # destination and makes mitmproxy log a misleading forwarding error.
    for path in (Path("/proc/net/tcp"), Path("/proc/net/tcp6")):
        try:
            lines = path.read_text().splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            fields = line.split()
            if len(fields) > 3 and fields[3] == "0A":
                if int(fields[1].rsplit(":", 1)[1], 16) == port:
                    return True
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

    def respond_json(self, value, status=200):
        payload = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        route = urlsplit(self.path).path
        if route == "/status":
            upstream_path = RUN_DIR / "upstream-tls.json"
            upstream = json.loads(upstream_path.read_text()) if upstream_path.exists() else {}
            configured = configured_settings(STATE_CONFIG)
            token = WEB_TOKEN.read_text().strip() if WEB_TOKEN.exists() else None
            return self.respond_json({"ready": proxy_ready(),
                                      "authority": authority_details(upstream.get("emudhra_old", False)),
                                      "verify_upstream_tls": upstream.get("verify_upstream_tls"),
                                      "configured_verify_upstream_tls": configured["verify_upstream_tls"],
                                      "emudhra_old": upstream.get("emudhra_old"),
                                      "configured_emudhra_old": configured["emudhra_old"],
                                      "mitmweb": {"ready": web_ready(), "token": token}})
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

    def do_PUT(self):
        if urlsplit(self.path).path != "/settings":
            self.send_error(404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 1024:
                raise ValueError("Invalid settings length")
            patch = json.loads(self.rfile.read(length))
            if (not isinstance(patch, dict) or not patch or
                    set(patch) - {"verify_upstream_tls", "emudhra_old"} or
                    any(not isinstance(value, bool) for value in patch.values())):
                raise ValueError("Expected boolean proxy settings")
            settings = {**configured_settings(STATE_CONFIG), **patch}
        except (ValueError, json.JSONDecodeError):
            return self.respond_json({"error": "Invalid upstream TLS setting"}, 400)

        STATE_CONFIG.parent.mkdir(parents=True, exist_ok=True)
        temporary = None
        try:
            with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=STATE_CONFIG.parent,
                                             prefix=".settings-", delete=False) as target:
                temporary = Path(target.name)
                os.fchmod(target.fileno(), 0o600)
                json.dump(settings, target)
                target.write("\n")
            temporary.replace(STATE_CONFIG)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
        self.respond_json(settings)


class UnixHTTPServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


if __name__ == "__main__":
    SOCKET_PATH.parent.mkdir(parents=True, exist_ok=True)
    SOCKET_PATH.unlink(missing_ok=True)
    with UnixHTTPServer(str(SOCKET_PATH), Handler) as server:
        os.chmod(SOCKET_PATH, 0o660)
        server.serve_forever()

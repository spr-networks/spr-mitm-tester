"""Challenge every SNI connection and record bounded application data previews."""

import base64
import asyncio
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

from mitmproxy import ctx

STATE_DIR = Path(os.environ.get("MITM_TESTER_STATE_DIR", "/state/plugins/spr-mitm-tester"))
EVENTS = STATE_DIR / "events.jsonl"
SETTINGS = STATE_DIR / "settings.json"
RUN_DIR = Path(os.environ.get("MITM_TESTER_RUN_DIR", "/run/mitm-tester"))
MAX_BYTES = 2_000_000
BODY_PREVIEW_BYTES = 8192
HEADER_CHARS = 8192
URL_CHARS = 4096


class MITMTesterProbe:
    def __init__(self):
        self.pending = {}
        self.completed = set()
        self.authority = json.loads((RUN_DIR / "authority.json").read_text())
        self.settings_task = None

    def running(self):
        # The active file is created by startup.sh; standalone addon tests omit it.
        if (RUN_DIR / "upstream-tls.json").exists():
            self.settings_task = asyncio.create_task(self.watch_settings())

    def done(self):
        if self.settings_task:
            self.settings_task.cancel()

    async def watch_settings(self):
        while True:
            try:
                if SETTINGS.exists():
                    settings = json.loads(SETTINGS.read_text())
                    if (not isinstance(settings, dict) or set(settings) != {"verify_upstream_tls"}
                            or not isinstance(settings["verify_upstream_tls"], bool)):
                        raise ValueError("Invalid upstream TLS setting")
                    verify = settings["verify_upstream_tls"]
                    if ctx.options.ssl_insecure != (not verify):
                        ctx.options.update(ssl_insecure=not verify)
                        active = RUN_DIR / "upstream-tls.json"
                        temporary = active.with_suffix(".tmp")
                        temporary.write_text(json.dumps({"verify_upstream_tls": verify}) + "\n")
                        temporary.replace(active)
            except (OSError, ValueError) as error:
                logging.warning("Could not apply upstream TLS setting: %s", error)
            await asyncio.sleep(1)

    def emit(self, event):
        event.update(
            time=datetime.now(timezone.utc).isoformat(),
            authority=self.authority["name"],
            issuer=self.authority["issued_by"],
        )
        EVENTS.parent.mkdir(parents=True, exist_ok=True)
        # Requests may contain credentials, so keep the bounded local log private.
        if EVENTS.exists() and EVENTS.stat().st_size > MAX_BYTES:
            with EVENTS.open("rb") as source:
                source.seek(-MAX_BYTES // 2, os.SEEK_END)
                source.readline()
                tail = source.read()
            EVENTS.write_bytes(tail)
        descriptor = os.open(EVENTS, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "a", encoding="utf-8") as target:
            target.write(json.dumps(event, separators=(",", ":")) + "\n")

    @staticmethod
    def client_fields(client):
        return {
            "connection_id": str(client.id),
            "client_ip": client.peername[0] if client.peername else "unknown",
            "sni": client.sni or "",
        }

    @staticmethod
    def data_fields(content, force_base64=False):
        preview = content[:BODY_PREVIEW_BYTES]
        try:
            value = preview.decode("utf-8")
            if force_base64 or any(
                not character.isprintable() and character not in "\r\n\t" for character in value
            ):
                raise ValueError("binary data")
            encoding = "utf-8"
        except (UnicodeDecodeError, ValueError):
            value = base64.b64encode(preview).decode("ascii")
            encoding = "base64"
        return {
            "data_bytes": len(content),
            "data_preview": value,
            "data_encoding": encoding,
            "data_truncated": len(content) > len(preview),
        }

    def tls_clienthello(self, data):
        client = data.context.client
        client_ip = client.peername[0] if client.peername else "unknown"
        sni = data.client_hello.sni
        # Without SNI, mitmproxy cannot reliably mint a matching leaf name.
        if not sni:
            data.ignore_connection = True
            return
        self.pending[client.id] = {
            "connection_id": str(client.id), "client_ip": client_ip, "sni": sni
        }
        self.emit({**self.pending[client.id], "result": "attempted"})

    def tls_established_client(self, data):
        probe = self.pending.pop(data.context.client.id, None)
        if probe:
            self.completed.add(data.context.client.id)
            self.emit({**probe, "result": "handshake_completed"})

    def tls_established_server(self, data):
        client = data.context.client
        if client.sni:
            self.emit({**self.client_fields(client), "result": "upstream_tls_completed"})

    def tls_failed_client(self, data):
        probe = self.pending.pop(data.context.client.id, None)
        if probe:
            self.emit({**probe, "result": "handshake_failed", "detail": data.conn.error or "unknown"})

    def tls_failed_server(self, data):
        client = data.context.client
        if client.sni:
            self.emit({
                **self.client_fields(client),
                "result": "upstream_tls_failed",
                "detail": (data.conn.error or "unknown")[:512],
            })

    def server_connect_error(self, data):
        if data.client.sni:
            self.emit({
                **self.client_fields(data.client),
                "result": "upstream_connect_failed",
                "detail": (data.server.error or "unknown")[:512],
            })

    def client_disconnected(self, client):
        probe = self.pending.pop(client.id, None)
        if probe:
            self.emit({**probe, "result": "disconnected_before_result"})
        if client.id in self.completed:
            self.completed.remove(client.id)
            self.emit({
                **self.client_fields(client),
                "result": "connection_closed",
                "detail": (client.error or "")[:512],
            })

    @staticmethod
    def request_fields(request):
        headers = []
        remaining = HEADER_CHARS
        headers_truncated = False
        for name, value in request.headers.items(multi=True):
            if remaining <= 0:
                headers_truncated = True
                break
            name = name[:min(256, remaining)]
            remaining -= len(name)
            clipped_value = value[:remaining]
            remaining -= len(clipped_value)
            headers.append([name, clipped_value])
            if len(clipped_value) != len(value):
                headers_truncated = True
                break
        url = request.pretty_url
        return {
            "method": request.method,
            "url": url[:URL_CHARS],
            "url_truncated": len(url) > URL_CHARS,
            "headers": headers,
            "headers_truncated": headers_truncated,
        }

    @staticmethod
    def body_fields(capture):
        preview = bytes(capture["preview"])
        try:
            body_preview = preview.decode("utf-8")
            body_encoding = "utf-8"
        except UnicodeDecodeError:
            body_preview = base64.b64encode(preview).decode("ascii")
            body_encoding = "base64"
        return {
            "body_bytes": capture["body_bytes"],
            "body_preview": body_preview,
            "body_encoding": body_encoding,
            "body_truncated": capture["body_bytes"] > len(preview),
        }

    def requestheaders(self, flow):
        capture = {"body_bytes": 0, "preview": bytearray()}
        flow.metadata["mitm_tester_request"] = capture
        self.emit({
            **self.client_fields(flow.client_conn),
            **self.request_fields(flow.request),
            "result": "request_headers",
            "request_id": flow.id,
        })

        def forward_and_capture(chunk):
            if chunk:
                capture["body_bytes"] += len(chunk)
                remaining = BODY_PREVIEW_BYTES - len(capture["preview"])
                if remaining:
                    capture["preview"].extend(chunk[:remaining])
            return chunk

        flow.request.stream = forward_and_capture

    def request(self, flow):
        capture = flow.metadata.pop("mitm_tester_request", {"body_bytes": 0, "preview": bytearray()})
        client = flow.client_conn
        self.emit({
            **self.request_fields(flow.request),
            **self.body_fields(capture),
            "result": "request",
            "request_id": flow.id,
            "connection_id": str(client.id),
            "client_ip": client.peername[0] if client.peername else "unknown",
            "sni": client.sni or "",
        })

    def error(self, flow):
        client = flow.client_conn
        capture = flow.metadata.pop("mitm_tester_request", None)
        detail = str(flow.error or "unknown")[:512]
        if capture is not None:
            self.emit({
                **self.client_fields(client),
                **self.request_fields(flow.request),
                **self.body_fields(capture),
                "result": "request_incomplete",
                "request_id": flow.id,
                "detail": detail,
            })
        else:
            self.emit({
                **self.client_fields(client),
                "result": "http_error",
                "request_id": flow.id,
                "detail": detail,
            })

    def responseheaders(self, flow):
        self.emit({
            "result": "upstream_response",
            "request_id": flow.id,
            "connection_id": str(flow.client_conn.id),
            "status_code": flow.response.status_code,
        })
        flow.response.stream = True

    def websocket_start(self, flow):
        self.emit({**self.client_fields(flow.client_conn),
                   "result": "websocket_opened", "request_id": flow.id})

    def websocket_message(self, flow):
        message = flow.websocket.messages[-1]
        self.emit({
            **self.client_fields(flow.client_conn),
            **self.data_fields(message.content, force_base64=not message.is_text),
            "result": "websocket_message",
            "request_id": flow.id,
            "direction": "client_to_server" if message.from_client else "server_to_client",
            "message_type": "text" if message.is_text else "binary",
        })

    def tcp_start(self, flow):
        self.emit({**self.client_fields(flow.client_conn), "result": "tcp_opened"})

    def tcp_message(self, flow):
        message = flow.messages[-1]
        self.emit({
            **self.client_fields(flow.client_conn),
            **self.data_fields(message.content),
            "result": "tcp_data",
            "direction": "client_to_server" if message.from_client else "server_to_client",
        })

    def tcp_error(self, flow):
        self.emit({
            **self.client_fields(flow.client_conn),
            "result": "tcp_error",
            "detail": str(flow.error or "unknown")[:512],
        })


addons = [MITMTesterProbe()]

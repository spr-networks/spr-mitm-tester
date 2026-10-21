"""Challenge every SNI-bearing connection and record bounded HTTP request previews."""

import base64
import json
import os
from datetime import datetime, timezone
from pathlib import Path

EVENTS = Path(os.environ.get("MITM_TESTER_STATE_DIR", "/state/plugins/spr-mitm-tester")) / "events.jsonl"
RUN_DIR = Path(os.environ.get("MITM_TESTER_RUN_DIR", "/run/mitm-tester"))
MAX_BYTES = 2_000_000
BODY_PREVIEW_BYTES = 8192
HEADER_CHARS = 8192
URL_CHARS = 4096


class MITMTesterProbe:
    def __init__(self):
        self.pending = {}
        self.authority = json.loads((RUN_DIR / "authority.json").read_text())

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

    def tls_clienthello(self, data):
        client = data.context.client
        client_ip = client.peername[0] if client.peername else "unknown"
        sni = data.client_hello.sni
        # Without SNI, mitmproxy cannot reliably mint a matching leaf name.
        if not sni:
            data.ignore_connection = True
            return
        self.pending[client.id] = {"client_ip": client_ip, "sni": sni}
        self.emit({**self.pending[client.id], "result": "attempted"})

    def tls_established_client(self, data):
        probe = self.pending.pop(data.context.client.id, None)
        if probe:
            self.emit({**probe, "result": "handshake_completed"})

    def tls_failed_client(self, data):
        probe = self.pending.pop(data.context.client.id, None)
        if probe:
            self.emit({**probe, "result": "handshake_failed", "detail": data.conn.error or "unknown"})

    def client_disconnected(self, client):
        probe = self.pending.pop(client.id, None)
        if probe:
            self.emit({**probe, "result": "disconnected_before_result"})

    def requestheaders(self, flow):
        capture = {"body_bytes": 0, "preview": bytearray()}
        flow.metadata["mitm_tester_request"] = capture

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
        headers = []
        remaining = HEADER_CHARS
        headers_truncated = False
        for name, value in flow.request.headers.items(multi=True):
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

        preview = bytes(capture["preview"])
        try:
            body_preview = preview.decode("utf-8")
            body_encoding = "utf-8"
        except UnicodeDecodeError:
            body_preview = base64.b64encode(preview).decode("ascii")
            body_encoding = "base64"
        url = flow.request.pretty_url
        client = flow.client_conn
        self.emit({
            "result": "request",
            "request_id": flow.id,
            "client_ip": client.peername[0] if client.peername else "unknown",
            "sni": client.sni or "",
            "method": flow.request.method,
            "url": url[:URL_CHARS],
            "url_truncated": len(url) > URL_CHARS,
            "headers": headers,
            "headers_truncated": headers_truncated,
            "body_bytes": capture["body_bytes"],
            "body_preview": body_preview,
            "body_encoding": body_encoding,
            "body_truncated": capture["body_bytes"] > len(preview),
        })

    def responseheaders(self, flow):
        flow.response.stream = True


addons = [MITMTesterProbe()]

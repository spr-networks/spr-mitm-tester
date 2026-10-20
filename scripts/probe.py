"""One certificate challenge per client IP and SNI; persist only TLS metadata."""

import json
import os
from datetime import datetime, timezone
from pathlib import Path

EVENTS = Path(os.environ.get("MITM_TESTER_STATE_DIR", "/state/plugins/spr-mitm-tester")) / "events.jsonl"
RUN_DIR = Path(os.environ.get("MITM_TESTER_RUN_DIR", "/run/mitm-tester"))
MAX_BYTES = 2_000_000


class MITMTesterProbe:
    def __init__(self):
        self.attempted = set()
        self.pending = {}
        self.authority = json.loads((RUN_DIR / "authority.json").read_text())

    def emit(self, event):
        event.update(
            time=datetime.now(timezone.utc).isoformat(),
            authority=self.authority["name"],
            issuer=self.authority["issued_by"],
        )
        EVENTS.parent.mkdir(parents=True, exist_ok=True)
        # Keep a bounded local audit trail. Only connection metadata is written.
        if EVENTS.exists() and EVENTS.stat().st_size > MAX_BYTES:
            with EVENTS.open("rb") as source:
                source.seek(-MAX_BYTES // 2, os.SEEK_END)
                source.readline()
                tail = source.read()
            EVENTS.write_bytes(tail)
        with EVENTS.open("a", encoding="utf-8") as target:
            target.write(json.dumps(event, separators=(",", ":")) + "\n")

    def tls_clienthello(self, data):
        client = data.context.client
        client_ip = client.peername[0] if client.peername else "unknown"
        sni = data.client_hello.sni
        # Without SNI, mitmproxy cannot reliably mint a matching leaf name.
        if not sni:
            data.ignore_connection = True
            return
        target = (client_ip, sni)
        if target in self.attempted:
            data.ignore_connection = True
            return
        self.attempted.add(target)
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
        # Stream bodies through; never accumulate them for this audit.
        flow.request.stream = True

    def responseheaders(self, flow):
        flow.response.stream = True


addons = [MITMTesterProbe()]

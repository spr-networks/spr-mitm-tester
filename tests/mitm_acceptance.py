"""Offline loopback test: a root-trusting client accepts a forged hostname leaf."""

import base64
import json
import os
import socket
import ssl
import subprocess
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


HOSTNAME = "www.whatever.com"
PLUGIN = Path("/plugin")
SCRATCH = Path("/scratch")
KEY = Path("/fixture/authority.key")
REQUEST_BODY = (
    b"\xff" + b"x" * 10000 if os.environ.get("TEST_BINARY") == "1"
    else json.dumps({"device": "sensor-7", "payload": "x" * 10000}).encode()
)


class UpstreamHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        received = self.rfile.read(int(self.headers["Content-Length"]))
        body = b"upstream-ok:" + received
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


def make_upstream_certificate():
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, HOSTNAME)])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(HOSTNAME)]), False)
        .sign(key, hashes.SHA256())
    )
    (SCRATCH / "upstream.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (SCRATCH / "upstream.key").write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_for_proxy(process, port, logfile):
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AssertionError(f"mitmdump exited: {logfile.read_text()[-2000:]}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.1)
    raise AssertionError(f"mitmdump did not listen: {logfile.read_text()[-2000:]}")


def connect_through_proxy(proxy_port, upstream_port, trust_file, trust_intermediate):
    raw = socket.create_connection(("127.0.0.1", proxy_port), timeout=10)
    raw.settimeout(10)
    raw.sendall(
        f"CONNECT {HOSTNAME}:{upstream_port} HTTP/1.1\r\nHost: {HOSTNAME}:{upstream_port}\r\n\r\n".encode()
    )
    headers = b""
    while b"\r\n\r\n" not in headers:
        chunk = raw.recv(4096)
        if not chunk:
            raise AssertionError("proxy closed before CONNECT completed")
        headers += chunk
    assert headers.startswith(b"HTTP/1.1 200"), headers

    context = ssl.create_default_context(cafile=str(trust_file))
    if trust_intermediate:
        # Treat the intermediate as the client's trust anchor.
        context.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
    with context.wrap_socket(raw, server_hostname=HOSTNAME) as client:
        leaf = x509.load_der_x509_certificate(client.getpeercert(binary_form=True))
        client.sendall(
            f"POST /telemetry?unit=7 HTTP/1.1\r\nHost: {HOSTNAME}\r\n"
            f"X-Device: sensor-7\r\nContent-Type: application/octet-stream\r\n"
            f"Content-Length: {len(REQUEST_BODY)}\r\nConnection: close\r\n\r\n".encode()
            + REQUEST_BODY
        )
        response = b""
        while chunk := client.recv(4096):
            response += chunk
    assert b"upstream-ok:" + REQUEST_BODY in response, response[-500:]
    return leaf


def main():
    SCRATCH.mkdir(exist_ok=True)
    assert any(item[4][0] == "127.0.0.1" for item in socket.getaddrinfo(HOSTNAME, None))
    issuer = os.environ.get("TEST_ISSUER", "emsign")
    assert issuer in ("emsign", "aaa")
    trust = os.environ.get("TEST_TRUST", "root")
    assert trust in ("root", "intermediate")
    cert_file = PLUGIN / "data" / "certs" / f"em-ov-tls-ca-g3c-{issuer}.pem"
    root_file = PLUGIN / "data" / "roots" / (
        "emsign-root-tls-g3.pem" if issuer == "emsign" else "aaa-certificate-services.pem"
    )
    intermediate = x509.load_pem_x509_certificate(cert_file.read_bytes())
    run_dir = SCRATCH / "mitm"
    run_dir.mkdir()
    subprocess.run(
        [sys.executable, str(PLUGIN / "scripts" / "prepare_authority.py"),
         "--cert", str(cert_file), "--key", str(KEY),
         "--catalogue", str(PLUGIN / "data" / "affected-tls.json"),
         "--roots-dir", str(PLUGIN / "data" / "roots"),
         "--output", str(run_dir)],
        check=True,
    )
    make_upstream_certificate()
    server = HTTPServer(("127.0.0.1", 0), UpstreamHandler)
    upstream_port = server.server_address[1]
    upstream_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    upstream_tls.load_cert_chain(str(SCRATCH / "upstream.crt"), str(SCRATCH / "upstream.key"))
    server.socket = upstream_tls.wrap_socket(server.socket, server_side=True)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    proxy_port = free_port()
    env = dict(os.environ, MITM_TESTER_RUN_DIR=str(run_dir), MITM_TESTER_STATE_DIR=str(SCRATCH))
    logfile = SCRATCH / "mitmdump.log"
    try:
        with logfile.open("wb") as log:
            proxy = subprocess.Popen(
                ["mitmdump", "-q", "--mode", "regular", "--listen-host", "127.0.0.1",
                 "--listen-port", str(proxy_port), "--set", f"confdir={run_dir}",
                 "--set", "connection_strategy=eager", "--set", "ssl_insecure=true",
                 "--set", "stream_large_bodies=1", "-s", str(PLUGIN / "scripts" / "probe.py")],
                stdout=log, stderr=subprocess.STDOUT, env=env,
            )
            try:
                wait_for_proxy(proxy, proxy_port, logfile)
                trust_file = root_file if trust == "root" else cert_file
                leaf = connect_through_proxy(proxy_port, upstream_port, trust_file, trust == "intermediate")
                assert leaf.issuer == intermediate.subject
                sans = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
                assert HOSTNAME in sans.get_values_for_type(x509.DNSName)
                intermediate.public_key().verify(
                    leaf.signature, leaf.tbs_certificate_bytes, ec.ECDSA(leaf.signature_hash_algorithm)
                )
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    events_file = SCRATCH / "events.jsonl"
                    if events_file.exists():
                        events = [json.loads(line) for line in events_file.read_text().splitlines()]
                        completed = any(
                            event.get("result") == "handshake_completed"
                            and event.get("sni") == HOSTNAME
                            and event.get("client_ip") == "127.0.0.1"
                            and event.get("authority") == "EM OV TLS CA - G3C"
                            for event in events
                        )
                        request = next((event for event in events if event.get("result") == "request"), None)
                        if completed and request:
                            break
                    time.sleep(0.1)
                else:
                    raise AssertionError("no completed handshake and request recorded")
                assert request["method"] == "POST", request
                assert request["url"].endswith("/telemetry?unit=7"), request
                assert ["x-device", "sensor-7"] in [[name.lower(), value] for name, value in request["headers"]]
                assert request["body_bytes"] == len(REQUEST_BODY), request
                expected_encoding = "base64" if os.environ.get("TEST_BINARY") == "1" else "utf-8"
                expected_preview = (
                    base64.b64encode(REQUEST_BODY[:8192]).decode() if expected_encoding == "base64"
                    else REQUEST_BODY[:8192].decode()
                )
                assert request["body_preview"] == expected_preview, request
                assert request["body_encoding"] == expected_encoding, request
                assert request["body_truncated"] is True, request
                assert (events_file.stat().st_mode & 0o777) == 0o600
                print(f"PASS: {HOSTNAME} leaf signed by {intermediate.subject.rfc4514_string()} "
                      f"({issuer}, client trusts {trust})")
            finally:
                proxy.terminate()
                try:
                    proxy.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proxy.kill()
                    proxy.wait()
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()

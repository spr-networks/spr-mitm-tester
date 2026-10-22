"""Offline loopback test: a root-trusting client accepts a forged hostname leaf."""

import base64
import hashlib
import json
import os
import shutil
import socket
import socketserver
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
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        received = self.rfile.read(int(self.headers["Content-Length"]))
        body = b"upstream-ok:" + received
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        assert self.headers.get("Upgrade", "").lower() == "websocket"
        key = self.headers["Sec-WebSocket-Key"]
        accept = base64.b64encode(hashlib.sha1(
            (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()
        ).digest()).decode()
        self.send_response(101)
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept)
        self.end_headers()
        frame = self.rfile.read(2)
        assert frame[0] == 0x81 and frame[1] & 0x80
        length = frame[1] & 0x7f
        mask = self.rfile.read(4)
        payload = bytes(value ^ mask[index % 4] for index, value in enumerate(self.rfile.read(length)))
        assert payload == b"websocket-from-device"
        reply = b"websocket-from-server"
        self.wfile.write(b"\x81" + bytes([len(reply)]) + reply)
        self.wfile.flush()
        self.close_connection = True

    def log_message(self, *_args):
        pass


class QuietHTTPServer(HTTPServer):
    def handle_error(self, request, client_address):
        # A TLS-only client intentionally closes before an HTTP request.
        if isinstance(sys.exc_info()[1], BrokenPipeError):
            return
        super().handle_error(request, client_address)


class RawEchoHandler(socketserver.BaseRequestHandler):
    def handle(self):
        payload = self.request.recv(8192)
        self.request.sendall(b"\x20\x02\x00\x00" + payload)


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
            raise AssertionError(f"proxy exited: {logfile.read_text()[-2000:]}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.1)
    raise AssertionError(f"proxy did not listen: {logfile.read_text()[-2000:]}")


def tls_client_through_proxy(proxy_port, upstream_port, trust_file, trust_intermediate):
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
    return context.wrap_socket(raw, server_hostname=HOSTNAME)


def connect_through_proxy(proxy_port, upstream_port, trust_file, trust_intermediate):
    with tls_client_through_proxy(proxy_port, upstream_port, trust_file, trust_intermediate) as client:
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


def send_websocket_message(proxy_port, upstream_port, trust_file, trust_intermediate):
    with tls_client_through_proxy(proxy_port, upstream_port, trust_file, trust_intermediate) as client:
        key = base64.b64encode(b"0123456789abcdef").decode()
        client.sendall((
            f"GET /stream HTTP/1.1\r\nHost: {HOSTNAME}\r\nUpgrade: websocket\r\n"
            f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        ).encode())
        headers = b""
        while b"\r\n\r\n" not in headers:
            headers += client.recv(4096)
        assert headers.startswith(b"HTTP/1.1 101"), headers
        payload = b"websocket-from-device"
        mask = b"abcd"
        client.sendall(b"\x81" + bytes([0x80 | len(payload)]) + mask + bytes(
            value ^ mask[index % 4] for index, value in enumerate(payload)
        ))
        assert b"websocket-from-server" in client.recv(4096)


def send_raw_tcp_message(proxy_port, upstream_port, trust_file, trust_intermediate):
    with tls_client_through_proxy(proxy_port, upstream_port, trust_file, trust_intermediate) as client:
        payload = b"\x10\x0bMQTT-device"
        client.sendall(payload)
        assert client.recv(4096) == b"\x20\x02\x00\x00" + payload


def main():
    SCRATCH.mkdir(exist_ok=True)
    assert any(item[4][0] == "127.0.0.1" for item in socket.getaddrinfo(HOSTNAME, None))
    packaged = os.environ.get("TEST_PACKAGED") == "1"
    issuer = os.environ.get("TEST_ISSUER", "emsign")
    assert issuer in ("emsign", "aaa")
    trust = os.environ.get("TEST_TRUST", "root")
    assert trust in ("root", "intermediate")
    if packaged:
        assert issuer == "emsign", "the packaged image includes only the emSign example"
        scripts_dir = Path("/scripts")
        cert_file = scripts_dir / "example-authority.crt"
        root_file = scripts_dir / "roots" / "emsign-root-tls-g3.pem"
        key_file = scripts_dir / "example-authority.key"
    else:
        scripts_dir = PLUGIN / "scripts"
        cert_file = PLUGIN / "data" / "certs" / f"em-ov-tls-ca-g3c-{issuer}.pem"
        root_file = PLUGIN / "data" / "roots" / (
            "emsign-root-tls-g3.pem" if issuer == "emsign" else "aaa-certificate-services.pem"
        )
        key_file = KEY
    intermediate = x509.load_pem_x509_certificate(cert_file.read_bytes())
    run_dir = SCRATCH / "mitm"
    run_dir.mkdir()
    subprocess.run(
        [sys.executable, str(scripts_dir / "prepare_authority.py"),
         "--cert", str(cert_file), "--key", str(key_file),
         "--catalogue", str(scripts_dir / "affected-tls.json") if packaged else str(PLUGIN / "data" / "affected-tls.json"),
         "--roots-dir", str(scripts_dir / "roots") if packaged else str(PLUGIN / "data" / "roots"),
         "--output", str(run_dir)],
        check=True,
    )
    make_upstream_certificate()
    server = QuietHTTPServer(("127.0.0.1", 0), UpstreamHandler)
    upstream_port = server.server_address[1]
    upstream_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    upstream_tls.load_cert_chain(str(SCRATCH / "upstream.crt"), str(SCRATCH / "upstream.key"))
    server.socket = upstream_tls.wrap_socket(server.socket, server_side=True)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    raw_server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), RawEchoHandler)
    raw_server.daemon_threads = True
    raw_port = raw_server.server_address[1]
    raw_server.socket = upstream_tls.wrap_socket(raw_server.socket, server_side=True)
    raw_thread = threading.Thread(target=raw_server.serve_forever, daemon=True)
    raw_thread.start()
    proxy_port = free_port()
    probe_script = scripts_dir / "probe.py"
    if packaged:
        probe_script = run_dir / "probe.py"
        shutil.copyfile(scripts_dir / "probe.py", probe_script)
    env = dict(os.environ, MITM_TESTER_RUN_DIR=str(run_dir), MITM_TESTER_STATE_DIR=str(SCRATCH))
    verify_upstream = os.environ.get("TEST_VERIFY_UPSTREAM") == "1"
    proxy_binary = os.environ.get("MITM_TESTER_PROXY_BINARY", "mitmdump")
    assert proxy_binary in ("mitmdump", "mitmweb")
    proxy_args = [proxy_binary]
    if proxy_binary == "mitmdump":
        proxy_args.append("-q")
    else:
        proxy_args += ["--set", "web_host=127.0.0.1", "--set", f"web_port={free_port()}",
                       "--set", "web_open_browser=false", "--set", "web_password=test-token"]
    logfile = SCRATCH / "proxy.log"
    try:
        with logfile.open("wb") as log:
            proxy = subprocess.Popen(
                proxy_args + ["--mode", "regular", "--listen-host", "127.0.0.1",
                 "--listen-port", str(proxy_port), "--set", f"confdir={run_dir}",
                 "--set", "connection_strategy=eager",
                 "--set", f"ssl_insecure={'false' if verify_upstream else 'true'}",
                 "--set", "stream_large_bodies=1", "-s", str(probe_script)],
                stdout=log, stderr=subprocess.STDOUT, env=env,
            )
            try:
                wait_for_proxy(proxy, proxy_port, logfile)
                trust_file = root_file if trust == "root" else cert_file
                if verify_upstream:
                    try:
                        with tls_client_through_proxy(proxy_port, upstream_port, trust_file, False):
                            pass
                    except (OSError, ssl.SSLError):
                        pass
                    deadline = time.monotonic() + 5
                    while time.monotonic() < deadline:
                        events_file = SCRATCH / "events.jsonl"
                        if events_file.exists():
                            events = [json.loads(line) for line in events_file.read_text().splitlines()]
                            failures = [event for event in events if event.get("result") == "upstream_tls_failed"]
                            if failures:
                                assert failures[0]["sni"] == HOSTNAME, failures
                                assert failures[0]["client_ip"] == "127.0.0.1", failures
                                assert "certificate verify failed" in failures[0]["detail"].lower(), failures
                                print("PASS: upstream certificate verification failure is recorded")
                                break
                        time.sleep(0.1)
                    else:
                        raise AssertionError(f"upstream TLS failure was not recorded: {logfile.read_text()[-2000:]}")
                    return
                # A second connection from the same client IP and SNI must also
                # receive a forged leaf, rather than reverting to pass-through.
                for _ in range(2):
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
                        completed = [event for event in events if
                            event.get("result") == "handshake_completed"
                            and event.get("sni") == HOSTNAME
                            and event.get("client_ip") == "127.0.0.1"
                            and event.get("authority") == "EM OV TLS CA - G3C"
                        ]
                        requests = [event for event in events if event.get("result") == "request"]
                        request_headers = [event for event in events if event.get("result") == "request_headers"]
                        responses = [event for event in events if event.get("result") == "upstream_response"]
                        upstream_tls = [event for event in events if event.get("result") == "upstream_tls_completed"]
                        if (len(completed) >= 2 and len(request_headers) >= 2
                                and len(requests) >= 2 and len(responses) >= 2 and len(upstream_tls) >= 2):
                            break
                    time.sleep(0.1)
                else:
                    raise AssertionError("two completed handshakes, requests, and responses were not recorded")
                connection_ids = {event["connection_id"] for event in completed}
                assert len(connection_ids) == 2, completed
                assert {event["connection_id"] for event in requests} == connection_ids, requests
                assert {event["request_id"] for event in request_headers} == {
                    event["request_id"] for event in requests
                }, request_headers
                assert {event["connection_id"] for event in responses} == connection_ids, responses
                assert {event["request_id"] for event in responses} == {event["request_id"] for event in requests}
                assert all(event["status_code"] == 200 for event in responses), responses
                expected_encoding = "base64" if os.environ.get("TEST_BINARY") == "1" else "utf-8"
                expected_preview = (
                    base64.b64encode(REQUEST_BODY[:8192]).decode() if expected_encoding == "base64"
                    else REQUEST_BODY[:8192].decode()
                )
                for request in requests:
                    assert request["method"] == "POST", request
                    assert request["url"].endswith("/telemetry?unit=7"), request
                    assert ["x-device", "sensor-7"] in [[name.lower(), value] for name, value in request["headers"]]
                    assert request["body_bytes"] == len(REQUEST_BODY), request
                    assert request["body_preview"] == expected_preview, request
                    assert request["body_encoding"] == expected_encoding, request
                    assert request["body_truncated"] is True, request
                with tls_client_through_proxy(proxy_port, upstream_port, trust_file, trust == "intermediate"):
                    pass
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    events = [json.loads(line) for line in events_file.read_text().splitlines()]
                    closed_without_request = [event for event in events if
                        event.get("result") == "connection_closed"
                        and event.get("connection_id") not in connection_ids
                        and not any(item.get("result") in ("request_headers", "request")
                                    and item.get("connection_id") == event.get("connection_id")
                                    for item in events)
                    ]
                    if closed_without_request:
                        break
                    time.sleep(0.1)
                else:
                    raise AssertionError("TLS-only connection did not record its close")
                if issuer == "emsign" and trust == "root":
                    send_websocket_message(proxy_port, upstream_port, trust_file, False)
                    send_raw_tcp_message(proxy_port, raw_port, trust_file, False)
                    deadline = time.monotonic() + 5
                    while time.monotonic() < deadline:
                        events = [json.loads(line) for line in events_file.read_text().splitlines()]
                        websocket_data = [event for event in events if event.get("result") == "websocket_message"]
                        tcp_data = [event for event in events if event.get("result") == "tcp_data"]
                        if len(websocket_data) >= 2 and len(tcp_data) >= 2:
                            break
                        time.sleep(0.1)
                    else:
                        raise AssertionError(f"WebSocket or TCP data missing: {logfile.read_text()[-2000:]}")
                    assert {event["direction"] for event in websocket_data} == {
                        "client_to_server", "server_to_client"
                    }, websocket_data
                    assert {event["data_preview"] for event in websocket_data} == {
                        "websocket-from-device", "websocket-from-server"
                    }, websocket_data
                    assert all(event["data_encoding"] == "utf-8" for event in websocket_data)
                    assert {event["direction"] for event in tcp_data} == {
                        "client_to_server", "server_to_client"
                    }, tcp_data
                    assert all(event["data_encoding"] == "base64" for event in tcp_data), tcp_data
                    assert {base64.b64decode(event["data_preview"]) for event in tcp_data} == {
                        b"\x10\x0bMQTT-device", b"\x20\x02\x00\x00\x10\x0bMQTT-device"
                    }, tcp_data
                    assert len({event["connection_id"] for event in websocket_data}) == 1
                    assert len({event["connection_id"] for event in tcp_data}) == 1
                    assert websocket_data[0]["connection_id"] != tcp_data[0]["connection_id"]
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
        raw_server.shutdown()
        raw_server.server_close()


if __name__ == "__main__":
    main()

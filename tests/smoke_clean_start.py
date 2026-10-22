#!/usr/bin/env python3
"""Check that the published image starts its proxy without authority config."""

import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path


SOCKET_CLIENT = """\
import json, socket
s = socket.socket(socket.AF_UNIX)
s.connect('/state/plugins/spr-mitm-tester/socket.sock')
s.sendall(b'GET /status HTTP/1.1\\r\\nHost: plugin\\r\\nConnection: close\\r\\n\\r\\n')
parts = []
while True:
    data = s.recv(65536)
    if not data:
        break
    parts.append(data)
print(json.dumps(json.loads(b''.join(parts).split(b'\\r\\n\\r\\n', 1)[1])))
"""

SOCKET_PUT = """\
import json, socket, sys
body = json.dumps({'verify_upstream_tls': sys.argv[1] == 'true'}).encode()
s = socket.socket(socket.AF_UNIX)
s.connect('/state/plugins/spr-mitm-tester/socket.sock')
s.sendall(b'PUT /settings HTTP/1.1\\r\\nHost: plugin\\r\\nContent-Type: application/json\\r\\nContent-Length: ' + str(len(body)).encode() + b'\\r\\nConnection: close\\r\\n\\r\\n' + body)
parts = []
while True:
    data = s.recv(65536)
    if not data:
        break
    parts.append(data)
response = b''.join(parts)
assert b' 200 ' in response.split(b'\\r\\n', 1)[0], response
"""

MITMWEB_OPTION = """\
from pathlib import Path
for path in Path('/proc').glob('[0-9]*/cmdline'):
    args = path.read_bytes().split(b'\\0')
    if any(b'mitmweb' in arg for arg in args[:2]):
        print(next(arg.decode() for arg in args if arg.startswith(b'ssl_insecure=')))
        break
"""

MITMWEB_CHECK = """\
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import urlopen
token = Path('/state/plugins/spr-mitm-tester/mitmweb-token').read_text().strip()
assert len(token) >= 32
try:
    urlopen('http://127.0.0.1:8081/', timeout=5)
except HTTPError as error:
    assert error.code == 403
else:
    raise AssertionError('mitmweb did not require its token')
with urlopen('http://127.0.0.1:8081/?token=' + token, timeout=5) as response:
    assert response.status == 200
    assert 'text/html' in response.headers['Content-Type']
"""

WEB_FIREWALL_CHECK = """\
import subprocess
gateway = subprocess.check_output(['ip', '-4', 'route', 'show', 'default', 'dev', 'eth0'], text=True).split()[2]
rules = subprocess.check_output(['nft', 'list', 'chain', 'inet', 'mitm_tester', 'input'], text=True)
assert f'tcp dport 8081 ip saddr {gateway} accept' in rules, rules
assert 'tcp dport 8081 drop' in rules, rules
"""


def run(*args, check=True):
    return subprocess.run(args, check=check, capture_output=True, text=True)


def check_start(image, expected_verify, config_dir=None):
    command = [
        "docker", "run", "-d", "--cap-add", "NET_ADMIN",
        "--tmpfs", "/run/mitm-tester:mode=0700",
        "--tmpfs", "/state/plugins/spr-mitm-tester:mode=0700",
    ]
    if config_dir:
        command += ["--mount", f"type=bind,src={config_dir},dst=/configs/spr-mitm-tester,readonly"]
    command += ["--entrypoint", "/scripts/startup.sh", image]
    container = run(*command).stdout.strip()
    try:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            response = run("docker", "exec", container, "python3", "-c", SOCKET_CLIENT, check=False)
            if response.returncode == 0:
                status = json.loads(response.stdout)
                if (status.get("ready") and
                        status.get("authority", {}).get("name") == "EM OV TLS CA - G3C" and
                        status.get("verify_upstream_tls") is expected_verify and
                        status.get("mitmweb", {}).get("ready")):
                    assert len(status["mitmweb"]["token"]) >= 32
                    run("docker", "exec", container, "python3", "-c", MITMWEB_CHECK)
                    run("docker", "exec", container, "python3", "-c", WEB_FIREWALL_CHECK)
                    option = run("docker", "exec", container, "python3", "-c", MITMWEB_OPTION)
                    expected_option = f"ssl_insecure={'false' if expected_verify else 'true'}"
                    if option.stdout.strip() != expected_option:
                        raise AssertionError(f"mitmweb option: {option.stdout!r}")
                    for desired in (not expected_verify, expected_verify):
                        run("docker", "exec", container, "python3", "-c", SOCKET_PUT,
                            str(desired).lower())
                        apply_deadline = time.monotonic() + 10
                        while time.monotonic() < apply_deadline:
                            state = run("docker", "exec", container, "python3", "-c", SOCKET_CLIENT)
                            current = json.loads(state.stdout)
                            if (current.get("verify_upstream_tls") is desired and
                                    current.get("configured_verify_upstream_tls") is desired):
                                break
                            time.sleep(0.5)
                        else:
                            raise AssertionError(f"setting did not apply live: {current!r}")
                    print(f"PASS: proxy ready with upstream verification {expected_verify}")
                    return
            time.sleep(1)
        logs = run("docker", "logs", "--tail", "50", container, check=False)
        raise RuntimeError("clean install never became ready:\n" + logs.stdout + logs.stderr)
    finally:
        run("docker", "rm", "-f", container, check=False)


def main(image):
    check_start(image, True)
    with tempfile.TemporaryDirectory() as directory:
        (Path(directory) / "settings.json").write_text('{"verify_upstream_tls": false}\n')
        check_start(image, False, directory)


if __name__ == "__main__":
    main(sys.argv[1])

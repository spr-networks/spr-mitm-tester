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

MITMDUMP_OPTION = """\
from pathlib import Path
for path in Path('/proc').glob('[0-9]*/cmdline'):
    args = path.read_bytes().split(b'\\0')
    if any(b'mitmdump' in arg for arg in args[:2]):
        print(next(arg.decode() for arg in args if arg.startswith(b'ssl_insecure=')))
        break
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
                        status.get("verify_upstream_tls") is expected_verify):
                    option = run("docker", "exec", container, "python3", "-c", MITMDUMP_OPTION)
                    expected_option = f"ssl_insecure={'false' if expected_verify else 'true'}"
                    if option.stdout.strip() != expected_option:
                        raise AssertionError(f"mitmdump option: {option.stdout!r}")
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

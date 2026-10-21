#!/usr/bin/env python3
"""Check that the published image starts its proxy without authority config."""

import json
import subprocess
import sys
import time


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


def run(*args, check=True):
    return subprocess.run(args, check=check, capture_output=True, text=True)


def main(image):
    container = run(
        "docker", "run", "-d", "--cap-add", "NET_ADMIN",
        "--tmpfs", "/run/mitm-tester:mode=0700",
        "--tmpfs", "/state/plugins/spr-mitm-tester:mode=0700",
        "--entrypoint", "/scripts/startup.sh", image,
    ).stdout.strip()
    try:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            response = run("docker", "exec", container, "python3", "-c", SOCKET_CLIENT, check=False)
            if response.returncode == 0:
                status = json.loads(response.stdout)
                if status.get("ready") and status.get("authority", {}).get("name") == "EM OV TLS CA - G3C":
                    print("PASS: clean install starts the proxy with the bundled eMudhra authority")
                    return
            time.sleep(1)
        logs = run("docker", "logs", "--tail", "50", container, check=False)
        raise RuntimeError("clean install never became ready:\n" + logs.stdout + logs.stderr)
    finally:
        run("docker", "rm", "-f", container, check=False)


if __name__ == "__main__":
    main(sys.argv[1])

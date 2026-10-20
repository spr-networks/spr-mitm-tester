#!/usr/bin/env python3
"""Run the certificate-acceptance test in an offline, bounded Docker container."""

from pathlib import Path
import subprocess
import tempfile
from urllib.request import urlopen


PLUGIN = Path(__file__).resolve().parents[1]
IMAGE = "mitmproxy/mitmproxy@sha256:00b77b5d8804c8ad18cb6caefbf9d5849e895e8986c5ce011f4ae30f4385962f"
KEY_URL = (
    "https://gist.githubusercontent.com/Fluepke/9a103c7f990c3cc2fb5002f7476f2f48/"
    "raw/adecc309d3aed74c9590be1a7634b09dfcec1756/private.pem"
)


def main():
    with tempfile.TemporaryDirectory(prefix=".mitm-tester-test.", dir=PLUGIN.parent) as fixture:
        key_path = Path(fixture) / "authority.key"
        with urlopen(KEY_URL, timeout=20) as response:
            key_path.write_bytes(response.read())
        key_path.chmod(0o600)

        common = [
            "docker", "run", "--rm", "--network", "none",
            "--add-host", "www.whatever.com:127.0.0.1",
            "--read-only", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--pids-limit", "64", "--memory", "768m", "--cpus", "1",
            "--tmpfs", "/scratch:rw,nosuid,size=64m,mode=0700",
            "--mount", f"type=bind,src={PLUGIN},dst=/plugin,readonly",
            "--mount", f"type=bind,src={fixture},dst=/fixture,readonly",
            "-e", "HOME=/scratch", "-e", "TMPDIR=/scratch",
            "-e", "PYTHONDONTWRITEBYTECODE=1", "--entrypoint", "python3",
            IMAGE, "/plugin/tests/mitm_acceptance.py",
        ]
        image_index = common.index(IMAGE)
        for issuer in ("emsign", "aaa"):
            for trust in ("root", "intermediate"):
                print(f"Testing {issuer} chain with client trusting {trust}", flush=True)
                command = (
                    common[:image_index]
                    + ["-e", f"TEST_ISSUER={issuer}", "-e", f"TEST_TRUST={trust}"]
                    + common[image_index:]
                )
                subprocess.run(command, check=True)


if __name__ == "__main__":
    main()

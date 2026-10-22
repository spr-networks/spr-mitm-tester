#!/usr/bin/env python3
"""Exercise the packaged authority and addon in an offline proxy flow."""

import subprocess
import sys
from pathlib import Path


PLUGIN = Path(__file__).resolve().parents[1]


def main(image):
    subprocess.run(
        [
            "docker", "run", "--rm", "--network", "none",
            "--add-host", "www.whatever.com:127.0.0.1",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--pids-limit", "64", "--memory", "768m", "--cpus", "1",
            "--tmpfs", "/scratch:rw,nosuid,size=64m,mode=0700",
            "--mount", f"type=bind,src={PLUGIN},dst=/plugin,readonly",
            "-e", "HOME=/scratch", "-e", "TMPDIR=/scratch",
            "-e", "PYTHONDONTWRITEBYTECODE=1", "-e", "TEST_PACKAGED=1",
            "-e", "MITM_TESTER_PROXY_BINARY=mitmweb",
            "--entrypoint", "python3", image, "/plugin/tests/mitm_acceptance.py",
        ],
        check=True,
    )


if __name__ == "__main__":
    main(sys.argv[1])

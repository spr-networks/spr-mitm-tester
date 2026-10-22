#!/usr/bin/env python3
"""Exercise upstream eMudhra signing in an offline Docker container."""

import os
from pathlib import Path
import subprocess


PLUGIN = Path(__file__).resolve().parents[1]
IMAGE = "mitmproxy/mitmproxy@sha256:c8a3753de11fd8266afeb103e163f7b7ac6a4a568a707fa2e15b23d20acf4eba"


def main():
    uid, gid = os.getuid(), os.getgid()
    common = [
        "docker", "run", "--rm", "--network", "none",
        "--add-host", "www.whatever.com:127.0.0.1",
        "--read-only", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--user", f"{uid}:{gid}",
        "--pids-limit", "64", "--memory", "768m", "--cpus", "1",
        "--tmpfs", f"/scratch:rw,nosuid,size=64m,mode=0700,uid={uid},gid={gid}",
        "--mount", f"type=bind,src={PLUGIN},dst=/plugin,readonly",
        "-e", "HOME=/scratch", "-e", "TMPDIR=/scratch",
        "-e", "PYTHONDONTWRITEBYTECODE=1", "--entrypoint", "python3",
        IMAGE, "/plugin/tests/mitm_acceptance.py",
    ]
    image_index = common.index(IMAGE)
    for mode in ("modern", "old"):
        for trust in ("root", "intermediate"):
            print(f"Testing upstream {mode} chain with client trusting {trust}", flush=True)
            command = (
                common[:image_index]
                + ["-e", f"TEST_CHAIN_MODE={mode}", "-e", f"TEST_TRUST={trust}",
                   "-e", f"TEST_BINARY={int(mode == 'old' and trust == 'intermediate')}",
                   "-e", f"TEST_LIVE_SWITCH={int(mode == 'modern' and trust == 'root')}"]
                + common[image_index:]
            )
            subprocess.run(command, check=True)

    print("Testing upstream verification failure recording", flush=True)
    subprocess.run(
        common[:image_index] + ["-e", "TEST_CHAIN_MODE=modern", "-e", "TEST_TRUST=root",
                                "-e", "TEST_VERIFY_UPSTREAM=1"] + common[image_index:],
        check=True,
    )


if __name__ == "__main__":
    main()

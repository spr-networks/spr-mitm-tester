#!/usr/bin/env python3
"""Validate the persistent upstream TLS setting and write the active mode."""

import argparse
import json
from pathlib import Path


def verify_upstream_tls(config_path):
    if not config_path.exists():
        return True
    settings = json.loads(config_path.read_text())
    if not isinstance(settings, dict) or set(settings) != {"verify_upstream_tls"}:
        raise ValueError('settings.json must contain only "verify_upstream_tls"')
    value = settings["verify_upstream_tls"]
    if not isinstance(value, bool):
        raise ValueError('"verify_upstream_tls" must be true or false')
    return value


def configure(config_path, output_path):
    verify = verify_upstream_tls(config_path)
    output_path.write_text(json.dumps({"verify_upstream_tls": verify}) + "\n")
    return f"ssl_insecure={'false' if verify else 'true'}"


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=Path("/configs/spr-mitm-tester/settings.json"))
    parser.add_argument("--output", type=Path, default=Path("/run/mitm-tester/upstream-tls.json"))
    args = parser.parse_args()
    print(configure(args.config, args.output))

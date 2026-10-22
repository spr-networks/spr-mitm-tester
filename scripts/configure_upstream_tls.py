#!/usr/bin/env python3
"""Validate the persistent upstream TLS setting and write the active mode."""

import argparse
import json
from pathlib import Path

STATE_CONFIG = Path("/state/plugins/spr-mitm-tester/settings.json")
LEGACY_CONFIG = Path("/configs/spr-mitm-tester/settings.json")


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


def configured_verify_upstream_tls(config_path=STATE_CONFIG, fallback_path=LEGACY_CONFIG):
    return verify_upstream_tls(config_path if config_path.exists() else fallback_path)


def configure(config_path, output_path, fallback_path=None):
    verify = configured_verify_upstream_tls(config_path, fallback_path or config_path)
    output_path.write_text(json.dumps({"verify_upstream_tls": verify}) + "\n")
    return f"ssl_insecure={'false' if verify else 'true'}"


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=STATE_CONFIG)
    parser.add_argument("--fallback", type=Path, default=LEGACY_CONFIG)
    parser.add_argument("--output", type=Path, default=Path("/run/mitm-tester/upstream-tls.json"))
    args = parser.parse_args()
    print(configure(args.config, args.output, args.fallback))

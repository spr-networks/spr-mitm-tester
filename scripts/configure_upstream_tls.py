#!/usr/bin/env python3
"""Validate persistent proxy settings and write the active mode."""

import argparse
import json
from pathlib import Path

STATE_CONFIG = Path("/state/plugins/spr-mitm-tester/settings.json")
LEGACY_CONFIG = Path("/configs/spr-mitm-tester/settings.json")


DEFAULTS = {"verify_upstream_tls": True, "emudhra_old": False}


def load_settings(config_path):
    if not config_path.exists():
        return dict(DEFAULTS)
    settings = json.loads(config_path.read_text())
    if not isinstance(settings, dict) or not settings or set(settings) - set(DEFAULTS):
        raise ValueError("settings.json has unknown or missing settings")
    if any(not isinstance(value, bool) for value in settings.values()):
        raise ValueError("settings.json values must be true or false")
    return {**DEFAULTS, **settings}


def configured_settings(config_path=STATE_CONFIG, fallback_path=LEGACY_CONFIG):
    return load_settings(config_path if config_path.exists() else fallback_path)


def configured_verify_upstream_tls(config_path=STATE_CONFIG, fallback_path=LEGACY_CONFIG):
    return configured_settings(config_path, fallback_path)["verify_upstream_tls"]


def configure(config_path, output_path, fallback_path=None):
    settings = configured_settings(config_path, fallback_path or config_path)
    output_path.write_text(json.dumps(settings) + "\n")
    verify = settings["verify_upstream_tls"]
    emudhra_option = "--emudhra-old" if settings["emudhra_old"] else "--emudhra"
    return f"ssl_insecure={'false' if verify else 'true'} {emudhra_option}"


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=STATE_CONFIG)
    parser.add_argument("--fallback", type=Path, default=LEGACY_CONFIG)
    parser.add_argument("--output", type=Path, default=Path("/run/mitm-tester/upstream-tls.json"))
    args = parser.parse_args()
    print(configure(args.config, args.output, args.fallback))

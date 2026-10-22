import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "configure_upstream_tls.py"


class UpstreamTLSConfigTest(unittest.TestCase):
    def test_ui_setting_overrides_file_based_initial_setting(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state.json"
            fallback = Path(directory) / "legacy.json"
            output = Path(directory) / "active.json"
            fallback.write_text('{"verify_upstream_tls": false}')
            state.write_text('{"verify_upstream_tls": true}')
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--config", str(state),
                 "--fallback", str(fallback), "--output", str(output)],
                check=True, capture_output=True, text=True,
            )
            self.assertEqual(result.stdout.strip(), "ssl_insecure=false")
            self.assertEqual(json.loads(output.read_text()), {"verify_upstream_tls": True})

    def test_default_and_optional_insecure_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "settings.json"
            output = Path(directory) / "active.json"

            for contents, expected_option, expected_verify in (
                (None, "ssl_insecure=false", True),
                ('{"verify_upstream_tls": false}', "ssl_insecure=true", False),
                ('{"verify_upstream_tls": true}', "ssl_insecure=false", True),
            ):
                if contents is None:
                    config.unlink(missing_ok=True)
                else:
                    config.write_text(contents)
                result = subprocess.run(
                    [sys.executable, str(SCRIPT), "--config", str(config), "--output", str(output)],
                    check=True, capture_output=True, text=True,
                )
                self.assertEqual(result.stdout.strip(), expected_option)
                self.assertEqual(json.loads(output.read_text()),
                                 {"verify_upstream_tls": expected_verify})

    def test_rejects_invalid_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "settings.json"
            output = Path(directory) / "active.json"
            config.write_text('{"verify_upstream_tls": "false"}')
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--config", str(config), "--output", str(output)],
                capture_output=True, text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()

"""Check the SPR sink contract served by the plugin API."""

import importlib.util
import json
import sys
import tempfile
import threading
import unittest
from http.server import HTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
spec = importlib.util.spec_from_file_location("mitm_tester_api", ROOT / "scripts" / "api.py")
plugin_api = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plugin_api)


class SinkContractTest(unittest.TestCase):
    def test_live_sink_matches_network_capability(self):
        plugin = json.loads((ROOT / "plugin.json").read_text())
        self.assertEqual(plugin["Name"], plugin["URI"])
        self.assertRegex(plugin["Name"], r"^[a-z0-9-]+$")
        self.assertTrue(plugin["SandboxedUI"])
        self.assertTrue(plugin["HasTopology"])
        self.assertNotIn("InstallTokenPath", plugin)
        self.assertNotIn("ScopedPaths", plugin)

        plugin_api.container_ip = lambda: "172.30.120.2"
        plugin_api.proxy_ready = lambda: True
        server = HTTPServer(("127.0.0.1", 0), plugin_api.Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            with urlopen(f"http://127.0.0.1:{server.server_port}/topology", timeout=3) as response:
                topology = json.load(response)
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=3)

        self.assertEqual(len(topology["Sinks"]), 1)
        sink = topology["Sinks"][0]
        self.assertEqual(sink["Iface"], plugin["NetworkCapabilities"]["Interface"])
        self.assertEqual(sink["IP"], "172.30.120.2")
        self.assertTrue(sink["Online"])

    def test_upstream_tls_setting_is_validated_and_saved(self):
        with tempfile.TemporaryDirectory() as directory:
            original = plugin_api.STATE_CONFIG
            plugin_api.STATE_CONFIG = Path(directory) / "settings.json"
            server = HTTPServer(("127.0.0.1", 0), plugin_api.Handler)
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            try:
                url = f"http://127.0.0.1:{server.server_port}/settings"
                for body in (b'{"verify_upstream_tls":"false"}',
                             b'{"emudhra_old":"true"}',
                             b'{"verify_upstream_tls":false,"extra":1}'):
                    with self.assertRaises(HTTPError) as response:
                        urlopen(Request(url, data=body, method="PUT"), timeout=3)
                    self.assertEqual(response.exception.code, 400)
                    response.exception.close()
                    self.assertFalse(plugin_api.STATE_CONFIG.exists())
                with urlopen(Request(url, data=b'{"verify_upstream_tls":false}', method="PUT"), timeout=3) as response:
                    self.assertEqual(json.load(response),
                                     {"verify_upstream_tls": False, "emudhra_old": False})
                with urlopen(Request(url, data=b'{"emudhra_old":true}', method="PUT"), timeout=3) as response:
                    self.assertEqual(json.load(response),
                                     {"verify_upstream_tls": False, "emudhra_old": True})
                self.assertEqual(json.loads(plugin_api.STATE_CONFIG.read_text()),
                                 {"verify_upstream_tls": False, "emudhra_old": True})
                self.assertEqual(plugin_api.STATE_CONFIG.stat().st_mode & 0o777, 0o600)
            finally:
                server.shutdown()
                server.server_close()
                worker.join(timeout=3)
                plugin_api.STATE_CONFIG = original


if __name__ == "__main__":
    unittest.main()

"""Check the SPR sink contract served by the plugin API."""

import importlib.util
import json
import threading
import unittest
from http.server import HTTPServer
from pathlib import Path
from urllib.request import urlopen


ROOT = Path(__file__).resolve().parents[1]
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


if __name__ == "__main__":
    unittest.main()

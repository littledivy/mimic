import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mimic import proxy


class ProxyStateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.state_file = Path(self.temporary.name) / "state" / "proxy.json"
        self.environment = patch.dict(
            os.environ, {"MIMIC_STATE_FILE": str(self.state_file)}, clear=False
        )
        self.environment.start()

    def tearDown(self):
        self.environment.stop()
        self.temporary.cleanup()

    def test_state_is_private_and_round_trips(self):
        state = {"url": "http://127.0.0.1:9001", "token": "secret", "pid": 12}

        proxy.save_state(state)

        self.assertEqual(proxy.load_state(), state)
        mode = stat.S_IMODE(self.state_file.stat().st_mode)
        self.assertEqual(mode, 0o600)
        directory_mode = stat.S_IMODE(self.state_file.parent.stat().st_mode)
        self.assertEqual(directory_mode, 0o700)

    def test_invalid_state_is_ignored(self):
        self.state_file.parent.mkdir()
        self.state_file.write_text("not-json", encoding="utf-8")

        self.assertIsNone(proxy.load_state())

    def test_state_with_public_permissions_is_ignored(self):
        proxy.save_state({"url": "http://127.0.0.1:8081", "token": "secret"})
        self.state_file.chmod(0o644)

        self.assertIsNone(proxy.load_state())

    def test_non_loopback_state_url_is_ignored(self):
        proxy.save_state({"url": "https://proxy.example", "token": "secret"})

        self.assertIsNone(proxy.load_state())

    def test_malformed_state_url_is_ignored(self):
        proxy.save_state({"url": "http://[invalid", "token": "secret"})

        self.assertIsNone(proxy.load_state())

    def test_clear_only_removes_matching_state(self):
        proxy.save_state({"url": "http://127.0.0.1:8081", "token": "current"})

        self.assertFalse(proxy.clear_state(token="old"))
        self.assertTrue(self.state_file.exists())
        self.assertTrue(proxy.clear_state(token="current"))
        self.assertFalse(self.state_file.exists())

    def test_state_must_contain_url_and_token(self):
        self.state_file.parent.mkdir()
        self.state_file.write_text(json.dumps({"url": "local"}), encoding="utf-8")

        self.assertIsNone(proxy.load_state())


if __name__ == "__main__":
    unittest.main()

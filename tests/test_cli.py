import unittest
from contextlib import redirect_stdout
from io import StringIO
from types import SimpleNamespace
from unittest.mock import Mock, patch

from mimic.cli import _record_command, cmd_record


class RecordCommandTests(unittest.TestCase):
    def test_record_command_confines_and_authenticates_proxy(self):
        command = _record_command(
            ["mitmweb"],
            "192.168.1.10",
            8080,
            8081,
            "web-secret",
            ("mimic", "proxy-secret"),
        )

        self.assertIn("192.168.1.10", command)
        self.assertIn("web_password=web-secret", command)
        self.assertIn("proxyauth=mimic:proxy-secret", command)
        self.assertIn("web_open_browser=false", command)
        web_host = command.index("--web-host")
        self.assertEqual(command[web_host + 1], "127.0.0.1")

    def test_proxy_authentication_can_be_disabled_explicitly(self):
        command = _record_command(
            ["mitmweb"], "192.168.1.10", 8080, 8081, "web-secret"
        )

        self.assertFalse(any(value.startswith("proxyauth=") for value in command))

    @patch("mimic.cli.proxy.clear_state")
    @patch("mimic.cli.proxy.save_state")
    @patch("mimic.cli.proxy.load_state", return_value=None)
    @patch("mimic.cli.subprocess.Popen")
    @patch("mimic.cli._mitmweb_cmd", return_value=["mitmweb"])
    @patch("mimic.cli.secrets.token_hex", return_value="proxy-secret")
    @patch("mimic.cli.secrets.token_urlsafe", return_value="web-secret")
    def test_record_saves_and_removes_runtime_state(
        self,
        token_urlsafe,
        token_hex,
        mitmweb_cmd,
        popen,
        load_state,
        save_state,
        clear_state,
    ):
        process = Mock(pid=321)
        process.wait.return_value = 0
        process.poll.return_value = 0
        popen.return_value = process
        args = SimpleNamespace(
            listen_host="192.168.1.10",
            proxy_port=8080,
            web_port=8081,
            no_proxy_auth=False,
        )

        with redirect_stdout(StringIO()):
            cmd_record(args)

        save_state.assert_called_once_with(
            {
                "url": "http://127.0.0.1:8081",
                "token": "web-secret",
                "pid": 321,
                "proxy_host": "192.168.1.10",
                "proxy_port": 8080,
            }
        )
        clear_state.assert_called_once_with(token="web-secret")


if __name__ == "__main__":
    unittest.main()

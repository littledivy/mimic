import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from mimic import proxy
from mimic.sources.mitm import Mitm, MitmError


class MitmClientTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        state_file = Path(self.temporary.name) / "proxy.json"
        self.environment = patch.dict(
            os.environ,
            {"MIMIC_STATE_FILE": str(state_file)},
            clear=False,
        )
        self.environment.start()
        os.environ.pop("MITM_URL", None)
        os.environ.pop("MITM_TOKEN", None)

    def tearDown(self):
        self.environment.stop()
        self.temporary.cleanup()

    def test_loads_url_and_token_from_runtime_state(self):
        proxy.save_state({"url": "http://127.0.0.1:9001", "token": "runtime"})

        client = Mitm()

        self.assertEqual(client.url, "http://127.0.0.1:9001")
        self.assertEqual(client.token, "runtime")

    def test_state_token_is_not_sent_to_an_explicit_url(self):
        proxy.save_state({"url": "http://127.0.0.1:8081", "token": "runtime"})

        client = Mitm(url="https://proxy.example")

        self.assertEqual(client.url, "https://proxy.example")
        self.assertIsNone(client.token)

    def test_authentication_failure_is_reported(self):
        client = Mitm(url="http://127.0.0.1:8081", token="wrong")
        client._http.get = Mock(return_value=Mock(status_code=403))

        with self.assertRaisesRegex(MitmError, "authentication failed with 403"):
            client.flows()

    def test_flows_authenticates_with_the_coordinated_token(self):
        client = Mitm(url="http://127.0.0.1:8081", token="secret")
        auth = Mock(status_code=200)
        flows = Mock(status_code=200)
        flows.json.return_value = [{"id": "one"}]
        client._http.get = Mock(side_effect=[auth, flows])

        self.assertEqual(client.flows(), [{"id": "one"}])
        self.assertEqual(
            client._http.get.call_args_list[0].kwargs["headers"],
            {"Authorization": "Bearer secret"},
        )

    def test_clear_sends_the_xsrf_token(self):
        client = Mitm(url="http://127.0.0.1:8081", token="secret")
        client._http.get = Mock(return_value=Mock(status_code=200))
        client._http.cookies.set("_mitmproxy_xsrf", "xsrf-token")
        client._http.post = Mock(return_value=Mock(status_code=200))

        client.clear()

        client._http.post.assert_called_once_with(
            "http://127.0.0.1:8081/clear",
            headers={"X-XSRFToken": "xsrf-token"},
            timeout=15,
        )

    def test_clear_supports_legacy_xsrf_cookie(self):
        client = Mitm(url="http://127.0.0.1:8081", token="secret")
        client._http.get = Mock(return_value=Mock(status_code=200))
        client._http.cookies.set("_xsrf", "legacy-token")
        client._http.post = Mock(return_value=Mock(status_code=204))

        client.clear()

        self.assertEqual(
            client._http.post.call_args.kwargs["headers"],
            {"X-XSRFToken": "legacy-token"},
        )


if __name__ == "__main__":
    unittest.main()

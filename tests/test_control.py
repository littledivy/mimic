import json
from io import StringIO
import unittest
from unittest.mock import Mock

import requests

from mimic import AgentPolicy, AgentSession, ControlPlane, Session
from mimic.control import PROTOCOL, run_jsonl


def response(body):
    result = requests.Response()
    result.status_code = 200
    result._content = json.dumps(body).encode("utf-8")
    result._content_consumed = True
    result.encoding = "utf-8"
    return result


class ControlPlaneTests(unittest.TestCase):
    def make_control(self, *, policy=None, token=None, bodies=None):
        session = Session(
            "https://api.example.com",
            headers={"Authorization": "Bearer captured-secret"},
        )
        bodies = iter(bodies or [{"ok": True}])
        session._http.request = Mock(side_effect=lambda *args, **kw: response(next(bodies)))
        agent = AgentSession(session, policy or AgentPolicy())
        endpoints = [{"method": "GET", "path": "/v1/users/{user_id}", "status": 200}]
        return ControlPlane(agent, endpoints, mutation_approval_token=token), session

    def test_tools_and_history_are_versioned(self):
        control, _ = self.make_control()

        tools = control.handle({"id": "tools-1", "op": "tools"})
        history = control.handle({"id": "history-1", "op": "history"})

        self.assertEqual(tools["protocol"], PROTOCOL)
        self.assertEqual(tools["id"], "tools-1")
        self.assertTrue(tools["ok"])
        self.assertEqual(history["history"], [])

    def test_results_are_bounded_and_secret_values_are_redacted(self):
        body = {
            "access_token": "response-secret",
            "nested": {"Authorization": "Bearer another-secret"},
            "message": "use Bearer inline-secret",
        }
        control, _ = self.make_control(bodies=[body])

        result = control.handle(
            {"id": 1, "op": "request", "method": "GET", "path": "/v1/me"}
        )

        rendered = json.dumps(result)
        self.assertTrue(result["ok"])
        self.assertNotIn("response-secret", rendered)
        self.assertNotIn("another-secret", rendered)
        self.assertNotIn("inline-secret", rendered)
        self.assertEqual(result["result"]["access_token"], "[REDACTED]")

    def test_mutation_requires_out_of_band_capability(self):
        policy = AgentPolicy.read_write()
        control, session = self.make_control(policy=policy, token="operator-capability")

        denied = control.handle(
            {"op": "request", "method": "POST", "path": "/v1/messages"}
        )
        allowed = control.handle(
            {
                "op": "request",
                "method": "POST",
                "path": "/v1/messages",
                "json_body": {"text": "hello"},
                "approval_token": "operator-capability",
            }
        )

        self.assertFalse(denied["ok"])
        self.assertEqual(denied["error"]["code"], "ApprovalRequired")
        self.assertTrue(allowed["ok"])
        self.assertEqual(session._http.request.call_count, 1)
        self.assertNotIn("operator-capability", json.dumps(allowed))

    def test_replay_keeps_target_fixed_but_allows_body_overrides(self):
        control, session = self.make_control(bodies=[{"n": 1}, {"n": 2}])
        first = control.handle(
            {"op": "request", "method": "GET", "path": "/v1/items", "params": {"page": 1}}
        )

        replay = control.handle(
            {"op": "replay", "sequence": first["action"]["sequence"], "params": {"page": 2}}
        )

        self.assertTrue(replay["ok"])
        self.assertEqual(replay["replayed_from"], 1)
        self.assertEqual(session._http.request.call_count, 2)
        self.assertEqual(session._http.request.call_args.kwargs["params"], {"page": 2})

    def test_jsonl_returns_an_error_without_stopping_the_stream(self):
        control, _ = self.make_control()
        source = StringIO('not-json\n{"id":2,"op":"history"}\n')
        sink = StringIO()

        run_jsonl(control, source, sink)

        responses = [json.loads(line) for line in sink.getvalue().splitlines()]
        self.assertFalse(responses[0]["ok"])
        self.assertTrue(responses[1]["ok"])
        self.assertEqual(responses[1]["id"], 2)


if __name__ == "__main__":
    unittest.main()

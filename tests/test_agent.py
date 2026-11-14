import unittest
from unittest.mock import Mock

import requests

from mimic import AgentPolicy, AgentSession, Session
from mimic.agent import (
    AgentPolicyError,
    ApprovalRequired,
    RequestBudgetExceeded,
)


def response(body=b'{"ok": true}'):
    result = requests.Response()
    result.status_code = 200
    result._content = body
    result._content_consumed = True
    result.encoding = "utf-8"
    return result


class AgentSessionTests(unittest.TestCase):
    def make_session(self, policy=None):
        session = Session(
            "https://api.example.com",
            headers={"Authorization": "Bearer do-not-log"},
        )
        session._http.request = Mock(return_value=response())
        return AgentSession(session, policy), session._http.request

    def test_default_policy_is_read_only(self):
        agent, request = self.make_session()

        with self.assertRaises(AgentPolicyError):
            agent.request("POST", "/v1/messages", json_body={"text": "hello"})

        request.assert_not_called()
        self.assertEqual(agent.audit_log, ())

    def test_mutation_needs_per_call_approval(self):
        agent, request = self.make_session(AgentPolicy.read_write())

        with self.assertRaises(ApprovalRequired):
            agent.request("DELETE", "/v1/messages/1")
        request.assert_not_called()

        result = agent.request("DELETE", "/v1/messages/1", approved=True)

        self.assertEqual(result, {"ok": True})
        self.assertTrue(agent.audit_log[0].approved)

    def test_path_prefix_and_request_budget_are_enforced(self):
        policy = AgentPolicy(path_prefixes=("/v1/public",), request_budget=1)
        agent, request = self.make_session(policy)

        with self.assertRaises(AgentPolicyError):
            agent.request("GET", "/v1/admin")
        request.assert_not_called()

        agent.request("GET", "/v1/public/users")
        with self.assertRaises(RequestBudgetExceeded):
            agent.request("GET", "/v1/public/users/2")

    def test_audit_log_omits_query_values_headers_and_bodies(self):
        agent, _ = self.make_session()

        agent.request(
            "GET",
            "/v1/users?token=top-secret&view=full",
            params={"api_key": "also-secret"},
        )

        audit = agent.audit_log[0]
        rendered = repr(audit)
        self.assertEqual(audit.query_keys, ("token", "view"))
        self.assertNotIn("top-secret", rendered)
        self.assertNotIn("also-secret", rendered)
        self.assertNotIn("do-not-log", rendered)
        self.assertTrue(audit.request_fingerprint.startswith("sha256:"))

    def test_catalog_exposes_typed_safety_metadata(self):
        agent, _ = self.make_session(AgentPolicy.read_write())
        endpoints = [
            {
                "method": "GET",
                "path": "/v1/users/{user_id}",
                "sample_count": 3,
                "statuses": [200, 404],
            },
            {"method": "POST", "path": "/v1/messages", "status": 201},
        ]

        tools = agent.tool_catalog(endpoints)

        self.assertEqual(len(tools), 2)
        get_tool = next(tool for tool in tools if tool["action"]["method"] == "GET")
        post_tool = next(tool for tool in tools if tool["action"]["method"] == "POST")
        self.assertEqual(get_tool["input_schema"]["required"], ["user_id"])
        self.assertTrue(get_tool["action"]["read_only"])
        self.assertTrue(post_tool["action"]["approval_required"])


if __name__ == "__main__":
    unittest.main()

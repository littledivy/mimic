import json
import asyncio
import importlib.util
import os
import sys
import unittest
from unittest.mock import Mock

import requests

from mimic import AgentPolicy, AgentSession, ControlPlane, Session
from mimic.mcp_adapter import MCP_INSTRUCTIONS, McpBridge, create_mcp_server


def response():
    result = requests.Response()
    result.status_code = 200
    result._content = b'{"ok": true}'
    result._content_consumed = True
    result.encoding = "utf-8"
    return result


class McpAdapterTests(unittest.TestCase):
    def make_bridge(self, *, write=False):
        session = Session("https://api.example.com")
        session._http.request = Mock(return_value=response())
        policy = AgentPolicy.read_write() if write else AgentPolicy()
        endpoints = [
            {
                "method": "GET",
                "path": "/v1/users/{user_id}",
                "sample_count": 2,
                "statuses": [200],
            }
        ]
        if write:
            endpoints.append({"method": "POST", "path": "/v1/messages", "status": 201})
        control = ControlPlane(
            AgentSession(session, policy),
            endpoints,
            mutation_approval_token="operator-capability" if write else None,
        )
        return McpBridge(control), control, session

    def test_tools_carry_cross_harness_safety_annotations(self):
        bridge, _, _ = self.make_bridge(write=True)

        tools = bridge.tools()
        get_tool = next(tool for tool in tools if tool["name"].startswith("http_get"))
        post_tool = next(tool for tool in tools if tool["name"].startswith("http_post"))

        self.assertTrue(get_tool["annotations"]["readOnlyHint"])
        self.assertFalse(get_tool["annotations"]["destructiveHint"])
        self.assertTrue(post_tool["annotations"]["destructiveHint"])
        self.assertNotIn("approval_token", json.dumps(tools))

    def test_endpoint_tool_encodes_path_parameters(self):
        bridge, _, session = self.make_bridge()
        tool = next(tool for tool in bridge.tools() if tool["name"].startswith("http_get"))

        result = bridge.call(
            tool["name"], {"user_id": "a/b", "query": {"include": "teams"}}
        )

        self.assertTrue(result["ok"])
        self.assertEqual(session._http.request.call_args.args[1], "https://api.example.com/v1/users/a%2Fb")
        self.assertEqual(session._http.request.call_args.kwargs["params"], {"include": "teams"})

    def test_mutation_capability_is_injected_inside_executor(self):
        bridge, _, session = self.make_bridge(write=True)
        tool = next(tool for tool in bridge.tools() if tool["name"].startswith("http_post"))

        result = bridge.call(tool["name"], {"json_body": {"text": "hello"}})

        self.assertTrue(result["ok"])
        self.assertEqual(session._http.request.call_count, 1)
        self.assertNotIn("operator-capability", json.dumps(result))

    def test_sdk_server_can_be_constructed(self):
        bridge, control, _ = self.make_bridge()

        server = create_mcp_server(control)

        self.assertEqual(server.name, "mimic")
        self.assertIn("untrusted data", MCP_INSTRUCTIONS)
        self.assertGreaterEqual(len(bridge.tools()), 3)

    @unittest.skipUnless(importlib.util.find_spec("mcp"), "MCP extra is not installed")
    def test_stdio_server_negotiates_and_lists_tools(self):
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client

        fixture = os.path.join(os.path.dirname(__file__), "fixtures", "sample.har")

        async def inspect_server():
            parameters = StdioServerParameters(
                command=sys.executable,
                args=[
                    "-m",
                    "mimic.cli",
                    "agent",
                    "api.example.com",
                    "--har",
                    fixture,
                    "--transport",
                    "mcp",
                ],
            )
            async with stdio_client(parameters) as (read, write):
                async with ClientSession(read, write) as session:
                    initialized = await session.initialize()
                    listed = await session.list_tools()
                    history = await session.call_tool("mimic_history", {})
                    return initialized, listed, history

        initialized, listed, history = asyncio.run(inspect_server())

        self.assertEqual(initialized.serverInfo.name, "mimic")
        self.assertTrue(any(tool.name.startswith("http_get") for tool in listed.tools))
        self.assertFalse(history.isError)
        self.assertEqual(history.structuredContent["history"], [])


if __name__ == "__main__":
    unittest.main()

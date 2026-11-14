# Agent harness integration

Mimic is model- and harness-neutral. Its security boundary lives in
`AgentSession` and `ControlPlane`; adapters only translate a harness protocol
into that boundary. MCP over stdio is the default because it is supported by
Codex, OpenCode, Claude Code, and a broad ecosystem of agent clients.

Install the optional MCP dependency with Python 3.10 or newer:

```bash
pip install 'mimic-client[agent]'
```

The server is read-only unless write methods are explicitly granted:

```bash
mimic agent api.example.com --har /absolute/path/traffic.har
```

Every endpoint tool contains MCP read-only, destructive, idempotent, and
open-world annotations. The server also sends global instructions describing
scope, untrusted response data, budgets, and approval expectations. Harness
permission prompts are a second layer; Mimic still enforces its own origin,
method, path, response-size, and request-count policy.

## Codex

Add a project-local server to `.codex/config.toml` in a trusted repository:

```toml
[mcp_servers.mimic]
command = "mimic"
args = [
  "agent", "api.example.com",
  "--har", "/absolute/path/traffic.har",
  "--transport", "mcp",
]
```

Or configure it from the CLI:

```bash
codex mcp add mimic -- mimic agent api.example.com \
  --har /absolute/path/traffic.har --transport mcp
```

Codex CLI, the IDE extension, and the desktop app share MCP configuration on
the same Codex host. Use `/mcp` to inspect the connected tools.

## OpenCode

Add a local MCP server to `opencode.json`:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "mimic": {
      "type": "local",
      "command": [
        "mimic", "agent", "api.example.com",
        "--har", "/absolute/path/traffic.har",
        "--transport", "mcp"
      ],
      "enabled": true
    }
  },
  "permission": {
    "mimic_http_get_*": "allow",
    "mimic_http_post_*": "ask",
    "mimic_http_put_*": "ask",
    "mimic_http_patch_*": "ask",
    "mimic_http_delete_*": "ask",
    "mimic_mimic_replay": "ask"
  }
}
```

OpenCode prefixes MCP tool names with the server name. Keep state-changing and
replay tools on `ask`; do not use auto-approval for an active security session.

## Claude Code

Register the same stdio command:

```bash
claude mcp add mimic -- mimic agent api.example.com \
  --har /absolute/path/traffic.har --transport mcp
```

The server does not depend on Claude Code or call a particular model. Claude
Code is simply one MCP client among several.

## Custom harnesses

Use `--transport jsonl` for systems without MCP. Send one JSON object per line
and read one response per line:

```json
{"protocol":"mimic-agent/1","id":"1","op":"tools"}
{"protocol":"mimic-agent/1","id":"2","op":"request","method":"GET","path":"/v1/me"}
{"protocol":"mimic-agent/1","id":"3","op":"history"}
{"protocol":"mimic-agent/1","id":"4","op":"replay","sequence":1}
```

Malformed requests receive structured errors without stopping the stream.
Input lines and model-visible results are byte-bounded.

## Enabling writes

Write access requires all three grants: the method, the path scope, and a
mutation capability supplied outside model-visible tool arguments.

```bash
export MIMIC_APPROVAL_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
mimic agent api.example.com --har /absolute/path/traffic.har \
  --allow-method POST --path-prefix /v1/lab \
  --approval-token-env MIMIC_APPROVAL_TOKEN
```

For MCP, the capability remains inside the executor and is never included in a
tool schema or result. The harness should still prompt for tools marked
destructive. For raw JSON-lines clients, the operator must provide the token in
the individual mutation message; it is consumed for authorization but never
stored in history or returned.

Start a fresh server with a newly generated capability when changing scope.
Read-only mode is the recommended default for autonomous or unattended agents.

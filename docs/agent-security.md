# Agent-facing cybersecurity architecture

Mimic's useful core is already close to an intercepting-proxy workflow: it
captures authenticated traffic, groups endpoints, infers schemas, and replays a
session. Turning that into an agent-operated security tool requires a control
plane around those capabilities. The agent must never receive ambient network
authority merely because it can inspect a capture.

Only use active features against applications and accounts you are authorized
to test. Target ownership, scope, and approval are deployment concerns that the
library cannot infer from traffic alone.

## Threat model

Captured traffic is both sensitive and untrusted. It can contain bearer tokens,
cookies, personal data, attacker-controlled response text, and prompt-injection
content. An agent can also make mistakes at machine speed. The primary failure
modes are:

- captured credentials sent to an attacker-selected origin;
- unintended writes or destructive calls;
- unbounded request loops, response bodies, or model context;
- secrets copied into prompts, tool descriptions, logs, or findings;
- active testing that escapes the explicitly authorized target scope;
- replay of per-request signatures or tracing headers as if they were stable
  credentials;
- downloaded interception scripts changing after review.

## Current boundary

`Session` enforces exact HTTP(S) origins before network access. Extra origins
require an explicit constructor grant. It also applies a default timeout and a
decompressed response-size limit.

`AgentSession` adds method and path capabilities, a request budget, per-call
mutation approval, and an immutable-view audit log. The log stores path and
query-key names, but hashes payloads and responses rather than retaining their
values. `tool_catalog()` emits endpoint tools without captured headers or body
samples.

The agent transport is vendor-neutral. MCP over stdio is the primary adapter
for Codex, OpenCode, Claude Code, and other compatible clients. A small,
versioned JSON-lines protocol supports custom harnesses. Both adapters use the
same policy executor, redaction, output bounds, history, and replay store.

HAR and live mitmproxy captures now use the same normalization pipeline, so
route templates, sample selection, telemetry filtering, schemas, and prompt
budgets behave consistently across capture sources.

## Delivery sequence

1. **Control plane and evidence.** Add a versioned JSON/MCP transport around
   `AgentSession`, persisted append-only evidence records, named target scopes,
   concurrency/rate limits, and a human approval callback. Keep raw credentials
   in the executor process, never in model-visible tool arguments.
2. **Burp-style inspection.** Add searchable HTTP history, a redacted message
   viewer, editable repeater, comparison views, and export/import of scoped
   projects. Preserve the original capture as evidence and store edits as new
   derived messages.
3. **Passive analysis.** Run deterministic rules over captured messages for
   cookie flags, CORS, cache policy, transport headers, leaked secrets/PII,
   verbose errors, authentication drift, and schema anomalies. Findings should
   cite message IDs and include confidence, severity, and remediation.
4. **Bounded active analysis.** Generate schema-aware mutations, authorization
   differentials, and input-boundary probes. Require a signed/approved target
   scope, safe defaults, rate and request ceilings, idempotency awareness, and a
   kill switch. Never let model text directly become an unrestricted URL or
   payload loop.
5. **Extensibility.** Define narrow interfaces for capture providers, passive
   rules, mutation strategies, and evidence stores. Pin and verify third-party
   Frida assets before execution, and isolate plugins from the credential
   broker wherever practical.

The model should decide *what* authorized test to attempt using typed tools;
deterministic code must decide whether that action is in scope, approved,
bounded, recorded, and safe enough to execute.

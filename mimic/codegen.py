"""Turn captured endpoints into an ergonomic Python client, using an AI.

`mimic gen <host>` builds a digest of what mimic saw on the wire and sends it
to an AI generator. The AI writes a real, editable client
class -- named methods, body templates, response handling, and the multi-step
chaining that mobile APIs often need -- on top of mimic.App.
"""
import ast
import json
import re
import subprocess
import sys

# Maximum length for a single response body in the prompt
_MAX_BODY_CHARS = 500

# Patterns that may indicate instruction injection in response bodies
_INJECTION_PATTERNS = re.compile(
    r"(?i)(?:IGNORE|OVERRIDE|FORGET|DISREGARD|NEW\s+INSTRUCTIONS?"
    r"|SYSTEM\s+(?:PROMPT|OVERRIDE|INSTRUCTION)"
    r"|IMPORTANT\s*:.*?(?:INSTRUCT|COMMAND|OVERRIDE))"
)


def sanitize_body(body: str) -> str:
    """Sanitize a response body before including it in the AI prompt.

    Strips content that looks like injection, truncates long string values,
    and limits overall body size.
    """
    if not body:
        return ""

    # Detect probable instruction injection
    if _INJECTION_PATTERNS.search(body):
        return "<response body omitted>"

    # Preserve JSON structure while limiting string values
    try:
        obj = json.loads(body)
        obj = _truncate_json(obj)
        return json.dumps(obj, indent=2)
    except (json.JSONDecodeError, ValueError):
        pass

    # Non-JSON body: just truncate
    if len(body) > _MAX_BODY_CHARS:
        return body[:_MAX_BODY_CHARS] + "\n...(truncated)"
    return body


def _truncate_json(obj, max_str=120):
    """Recursively truncate string values in a JSON-like structure."""
    if isinstance(obj, dict):
        return {k: _truncate_json(v, max_str) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_truncate_json(v, max_str) for v in obj[:20]]
    elif isinstance(obj, str) and len(obj) > max_str:
        return obj[:max_str] + "..."
    return obj


def build_digest(endpoints):
    """Render the endpoint list into the block the AI reads.

    Response bodies are sanitized before inclusion to reduce the risk
    of prompt injection via captured HTTP response content.
    """
    parts = []
    for e in endpoints:
        block = [f"### {e['method']} {e['path']}  -> {e['status']}"]
        if e.get("query"):
            block.append(f"query: {e['query']}")
        if e.get("request_body"):
            block.append(f"request body:\n{e['request_body']}")
        if e.get("response_body"):
            block.append(f"response body:\n{sanitize_body(e['response_body'])}")
        parts.append("\n".join(block))
    return "\n\n".join(parts)


def build_prompt(host, endpoints):
    """Build the full AI prompt from host and endpoint data."""
    prompt = PROMPT.format(host=host, digest=build_digest(endpoints))
    if _INJECTION_PATTERNS.search(prompt):
        print("warning: possible injection detected in captured data", file=sys.stderr)
    return prompt


PROMPT = """\
You are writing a Python API client. Below is real captured HTTP traffic from \
the app `{host}`, recorded by a proxy while the user exercised the app with \
their own account. Your job: turn it into a clean, ergonomic client library.

Rules:
- Output ONE Python file, nothing else. No prose, no markdown fences.
- Subclass `mimic.App`. Set `HOST = "{host}"`. Auth/device headers are pulled \
automatically by the base class -- do NOT hardcode tokens or headers.
- Give methods human names for what they DO (get_posts, like, send_message), \
not the raw path. Infer intent from the path, bodies, and status codes.
- Use self.get(path)/self.post(path, json=body). Both return parsed JSON.
- If an endpoint's body reuses an id or token that another endpoint returns \
(e.g. a viewToken, a playerId, a session id), chain the calls: fetch the \
prerequisite inside the method or cache it on the instance. Read the sample \
bodies carefully to find these dependencies.
- Turn values that vary per call (ids, text, ratings) into method parameters. \
Keep values that are constant-for-this-user as defaults or instance state.
- Skip pure telemetry/analytics/config endpoints unless they're needed as a \
prerequisite for a real action.
- Add a one-line docstring per method. Keep it tight and readable.

Captured endpoints for {host}:

{digest}
"""


def generate(host, endpoints, model="sonnet", generator="claude"):
    """Run the AI generator on the prompt and return the generated Python source."""
    prompt = build_prompt(host, endpoints)
    try:
        if generator == "opencode":
            proc = subprocess.run(
                ["opencode", "run", prompt],
                capture_output=True, text=True, timeout=300,
            )
        else:
            proc = subprocess.run(
                ["claude", "-p", "--model", model],
                input=prompt, capture_output=True, text=True, timeout=300,
            )
    except FileNotFoundError:
        sys.exit(
            f"`{generator}` CLI not found -- install it, "
            "or use `mimic gen --prompt-only`"
        )
    if proc.returncode != 0:
        sys.exit(f"{generator} failed:\n{proc.stderr}")

    source = _strip_fences(proc.stdout)

    # Validate generated code before returning
    try:
        ast.parse(source)
    except SyntaxError:
        sys.exit("generated code did not parse as valid Python -- aborting")

    return source


def _strip_fences(text):
    """AI generators sometimes wrap output in ```python fences."""
    m = re.search(r"```(?:python)?\n(.*?)```", text, re.S)
    return (m.group(1) if m else text).strip() + "\n"

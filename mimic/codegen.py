"""Turn captured endpoints into an ergonomic Python client, using an AI.

`mimic gen <host>` builds a digest of what mimic saw on the wire and sends it
to an AI generator. The AI writes a real, editable client
class — named methods, body templates, response handling, and the multi-step
chaining that mobile APIs often need — on top of mimic.App.
"""
import re
import shutil
import subprocess
import sys


PROMPT = """\
You are writing a Python API client. Below is real captured HTTP traffic from \
the app `{host}`, recorded by a proxy while the user exercised the app with \
their own account. Your job: turn it into a clean, ergonomic client library.

Rules:
- Output ONE Python file, nothing else. No prose, no markdown fences.
- Subclass `mimic.App`. Set `HOST = "{host}"`. Auth/device headers are pulled \
automatically by the base class — do NOT hardcode tokens or headers.
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


def build_digest(endpoints):
    """Render the endpoint list into the block the AI reads."""
    parts = []
    for e in endpoints:
        block = [f"### {e['method']} {e['path']}  -> {e['status']}"]
        if e["query"]:
            block.append(f"query: {e['query']}")
        if e["request_body"]:
            block.append(f"request body:\n{e['request_body']}")
        if e["response_body"]:
            block.append(f"response body:\n{e['response_body']}")
        parts.append("\n".join(block))
    return "\n\n".join(parts)


def build_prompt(host, endpoints):
    return PROMPT.format(host=host, digest=build_digest(endpoints))


def generate(host, endpoints, model="sonnet", generator="claude"):
    """Run the AI generator on the prompt and return the generated Python source."""
    prompt = build_prompt(host, endpoints)
    # npm installs these CLIs as .cmd/.ps1 shims on Windows, which CreateProcess
    # won't find by bare name, so resolve to a full path first.
    exe = shutil.which(generator) or generator
    try:
        if generator == "opencode":
            proc = subprocess.run(
                [exe, "run", prompt],
                capture_output=True, text=True, timeout=300,
            )
        else:
            proc = subprocess.run(
                [exe, "-p", "--model", model],
                input=prompt, capture_output=True, text=True, timeout=300,
            )
    except FileNotFoundError:
        sys.exit(
            f"`{generator}` CLI not found — install it, "
            "or use `mimic gen --prompt-only`"
        )
    if proc.returncode != 0:
        # Claude Code prints failures like "Not logged in" on stdout, so falling
        # back to it keeps the real reason from being reported as a bare colon.
        detail = (proc.stderr or "").strip() or (proc.stdout or "").strip()
        if not detail:
            detail = f"exit status {proc.returncode}"
        sys.exit(f"{generator} failed:\n{detail}")
    return _strip_fences(proc.stdout)


def _strip_fences(text):
    """AI generators sometimes wrap output in ```python fences."""
    m = re.search(r"```(?:python)?\n(.*?)```", text, re.S)
    return (m.group(1) if m else text).strip() + "\n"

"""Turn captured endpoints into an ergonomic client, using an AI.

`mimic gen <host>` builds a digest of what mimic saw on the wire and sends it
to an AI generator. The AI writes a real, editable client
class — named methods, body templates, response handling, and the multi-step
chaining that mobile APIs often need — on top of the mimic runtime.

Two output languages are supported: Python (default, on top of `mimic.App`) and
TypeScript (`--lang ts`, on top of `MimicClient` with Zod-validated responses).
"""
import os
import re
import subprocess
import sys


# Runtime the generated client imports, per language. Python ships as an
# installed module (`from mimic import App`); TypeScript ships as a template
# file copied next to the generated client (`import { MimicClient }`).
_RUNTIME_TEMPLATES = {"ts": "mimic_client.ts"}


PROMPT_PY = """\
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


PROMPT_TS = """\
You are writing a TypeScript API client. Below is real captured HTTP traffic \
from the app `{host}`, recorded by a proxy while the user exercised the app \
with their own account. Your job: turn it into a clean, typed client library.

Rules:
- Output ONE TypeScript file, nothing else. No prose, no markdown fences.
- Import the runtime: `import {{ MimicClient, CallOptions }} from "./mimic_client";` \
and `import {{ z }} from "zod";`. The runtime file ships alongside this one — do \
NOT redefine MimicClient.
- Export one class that `extends MimicClient`. Do NOT hardcode tokens or \
headers; the caller supplies them via `new Client({{ baseUrl, headers }})` or \
`Client.fromCurl(...)`. Add a short usage comment at the top showing both.
- For each real endpoint, declare a Zod schema for its response inferred from \
the sample body (e.g. `const PostsSchema = z.object({{ ... }});`) and export an \
inferred type (`export type Posts = z.infer<typeof PostsSchema>;`). Prefer \
`z.array`, `z.string`, `z.number`, `z.boolean`, `.optional()`, `.nullable()`; \
use `z.unknown()` for shapes you cannot infer.
- Give methods human names for what they DO (getPosts, like, sendMessage), not \
the raw path. Infer intent from the path, bodies, and status codes. Type each \
method's return as `Promise<T>` and pass the schema through: \
`return this.get("/path", {{ schema: PostsSchema }});` / \
`return this.post("/path", body, {{ schema: ... }});`.
- If an endpoint's body reuses an id or token another endpoint returns (a \
viewToken, a playerId, a session id), chain the calls: fetch the prerequisite \
inside the method or cache it on the instance. Read the sample bodies for these.
- Turn values that vary per call (ids, text, ratings) into typed method \
parameters. Keep values constant-for-this-user as defaults or instance state.
- Skip pure telemetry/analytics/config endpoints unless needed as a \
prerequisite for a real action.
- Add a one-line JSDoc per method. Keep it tight and readable.

Captured endpoints for {host}:

{digest}
"""


PROMPTS = {"python": PROMPT_PY, "ts": PROMPT_TS}


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


def build_prompt(host, endpoints, lang="python"):
    return PROMPTS[lang].format(host=host, digest=build_digest(endpoints))


def generate(host, endpoints, model="sonnet", generator="claude", lang="python"):
    """Run the AI generator on the prompt and return the generated source."""
    prompt = build_prompt(host, endpoints, lang)
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
            f"`{generator}` CLI not found — install it, "
            "or use `mimic gen --prompt-only`"
        )
    if proc.returncode != 0:
        sys.exit(f"{generator} failed:\n{proc.stderr}")
    return _strip_fences(proc.stdout)


def write_runtime(lang, out_dir):
    """Place the language runtime next to a generated client, if it needs one.

    Returns the runtime's path when written (or already present), else None.
    Existing files are left untouched so local edits survive re-generation.
    """
    name = _RUNTIME_TEMPLATES.get(lang)
    if not name:
        return None
    dest = os.path.join(out_dir or ".", name)
    if not os.path.exists(dest):
        src = os.path.join(os.path.dirname(__file__), "templates", name)
        with open(src) as f:
            runtime = f.read()
        with open(dest, "w") as f:
            f.write(runtime)
    return dest


def _strip_fences(text):
    """AI generators sometimes wrap output in ```python / ```ts fences."""
    m = re.search(r"```(?:python|py|typescript|ts)?\n(.*?)```", text, re.S)
    return (m.group(1) if m else text).strip() + "\n"

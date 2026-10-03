"""Turn captured endpoints into an ergonomic Python client, using an AI.

`mimic gen <host>` builds a digest of what mimic saw on the wire and sends it
to an AI generator. The AI writes a real, editable client
class — named methods, body templates, response handling, and the multi-step
chaining that mobile APIs often need — on top of mimic.App.

Which generator runs is a lookup in `BACKENDS`, not a branch in `generate`.
Adding one is a table entry — `agy` is here because its prompt transport isn't
knowable in advance, so the entry declares it should be probed rather than
guessed at.
"""
import re
import shutil
import subprocess

from .errors import GeneratorError


#: How a backend takes its prompt: on stdin, as an argument, or unknown until
#: the binary is asked.
STDIN, ARGV, PROBE = "stdin", "argv", "probe"


class Backend:
    """One code generator: the command to run and how it wants its prompt.

    `prompt_via=PROBE` means nobody knows yet and the binary has to be asked at
    call time. `model_arg` is the flag that carries a model name, or None for a
    CLI that has no such concept.
    """

    __slots__ = ("name", "argv", "prompt_via", "model_arg", "hints")

    def __init__(self, name, argv, prompt_via, model_arg=None, hints=()):
        self.name = name
        self.argv = tuple(argv)
        self.prompt_via = prompt_via
        self.model_arg = model_arg
        self.hints = tuple(hints)

    def command(self, model=None):
        cmd = list(self.argv)
        if self.model_arg and model:
            cmd += [self.model_arg, model]
        return cmd

    def __repr__(self):
        return f"<Backend {self.name} prompt_via={self.prompt_via}>"


#: Every AI backend mimic can drive. The CLI resolves `--generator` through
#: this table, so a new generator is a row and nothing else.
BACKENDS = {
    "claude": Backend("claude", ["claude"], STDIN, model_arg="--model"),
    "opencode": Backend("opencode", ["opencode", "run"], ARGV),
    # `agy` renders `--prompt` and `-p` with no argument placeholder, yet `-p`
    # refuses to run without one — so its help cannot be trusted on its own,
    # and `hints` are only the starting guess `generate` then verifies by
    # trying. The two spellings are not interchangeable.
    "agy": Backend("agy", ["agy"], PROBE,
                   hints=("--prompt", "-p ", "usage:", "arguments")),
}

#: Probed prompt transports, one per backend per process. Probing costs a
#: subprocess, so it happens at most once and the answer is then known.
_PROBED = {}


def get_backend(name):
    """The named backend, or an error naming the ones that exist."""
    try:
        return BACKENDS[name]
    except KeyError:
        raise GeneratorError(
            f"unknown generator {name!r} — choose one of "
            f"{', '.join(sorted(BACKENDS))}, or 'deterministic'"
        )


def which(backend):
    """The absolute path of `backend`'s command, looked up on PATH.

    Nothing here hardcodes where a CLI lives: `agy` and `claude` are installed
    in different places on different machines, and a path baked into mimic
    would be wrong on most of them.
    """
    found = shutil.which(backend.argv[0])
    if found is None:
        raise GeneratorError(
            f"`{backend.name}` CLI not found on PATH — install it, or ask for a "
            f"generator that is installed ({', '.join(_installed())})"
        )
    return found


def _installed():
    return [n for n, b in BACKENDS.items() if shutil.which(b.argv[0])] or ["none"]


def detect_prompt_mode(backend):
    """Whether `backend` reads its prompt from stdin or wants it as an argument.

    Probed at call time and cached. The binary's own `--help` is read for a
    hint, but a hint is only a hint: `agy` renders `--prompt` with no argument
    placeholder even though `-p` refuses to run without one, so help text alone
    can be wrong. The guarantee is the retry in `generate` — a call that comes
    back non-zero with nothing on stdout means the prompt never arrived, and
    the other transport is tried. Whichever one works is remembered.
    """
    if backend.prompt_via != PROBE:
        return backend.prompt_via
    if backend.name in _PROBED:
        return _PROBED[backend.name]
    mode = _from_help(backend)
    _PROBED[backend.name] = mode
    return mode


def _from_help(backend):
    """Read the answer out of `--help`, or None when it isn't stated."""
    try:
        proc = subprocess.run([which(backend), "--help"], capture_output=True,
                              text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    text = (proc.stdout or "") + (proc.stderr or "")
    lowered = text.lower()
    if any(h in lowered for h in backend.hints if h != "usage:"):
        return ARGV
    if "stdin" in lowered:
        return STDIN
    return None


def _try(exe, backend, prompt, model, mode):
    """One attempt against the resolved binary. Returns the completed process."""
    cmd = backend.command(model)
    cmd[0] = exe
    if mode == ARGV:
        return subprocess.run(cmd + [prompt], capture_output=True, text=True,
                              timeout=300)
    return subprocess.run(cmd, input=prompt, capture_output=True, text=True,
                          timeout=300)


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
- If an endpoint is labelled `[query: Name]` or `[mutation: Name]`, it is \
GraphQL: every operation shares one URL, and the named variables are the \
arguments. Call it as self.post("<path>", {{"query": GQL, "operationName": \
"Name", "variables": {{...}}}}) and keep the query text as a module constant.
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
        heading = f"### {e['method']} {e['path']}"
        if e.get("operation"):
            heading += f"  [{e.get('operation_type', 'query')}: {e['operation']}]"
        block = [f"{heading}  -> {e['status']}"]
        if e.get("variables"):
            block.append(f"variables: {', '.join(e['variables'])}")
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
    """Run the named AI generator on the prompt and return the Python source.

    Raises `GeneratorError` if the CLI isn't installed or the call fails. It
    never quietly produces output some other way: a user who asked for an AI
    backend must be able to trust that the file they got came from it.
    """
    backend = get_backend(generator)
    exe = which(backend)
    prompt = build_prompt(host, endpoints)
    mode = detect_prompt_mode(backend)
    probed = backend.prompt_via == PROBE

    # A probed backend starts on whatever the help suggested (stdin when it
    # said nothing), and the observed result outranks that hint.
    first = mode or STDIN
    proc = _try(exe, backend, prompt, model, first)

    if probed and proc.returncode != 0 and not (proc.stdout or "").strip():
        # Non-zero with nothing on stdout means the prompt never arrived — the
        # one failure shape that means "wrong transport" rather than "the model
        # had a bad time". Try the other way once.
        other = ARGV if first == STDIN else STDIN
        retry = _try(exe, backend, prompt, model, other)
        if retry.returncode == 0 and (retry.stdout or "").strip():
            proc, first = retry, other

    if probed:
        _PROBED[backend.name] = first

    if proc.returncode != 0:
        # Not stderr specifically. `claude -p` reports "Not logged in · Please
        # run /login" on *stdout* and exits 1 with an empty stderr, so reading
        # only stderr turns the one line that says what to do into a bare exit
        # code — the diagnosis the user needs, thrown away.
        said = (proc.stderr or "").strip() or (proc.stdout or "").strip()
        raise GeneratorError(
            f"`{backend.name}` failed (exit {proc.returncode}):\n"
            f"{said or '(it printed nothing — check it is installed and logged in)'}"
        )
    return _strip_fences(proc.stdout)


def _strip_fences(text):
    """AI generators sometimes wrap output in ```python fences."""
    m = re.search(r"```(?:python)?\n(.*?)```", text, re.S)
    return (m.group(1) if m else text).strip() + "\n"

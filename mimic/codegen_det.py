"""A Python client inferred from a capture, with no AI in the loop.

`mimic gen` asks an AI to read a capture and write a client. That works, and
it also does something uncomfortable: the types in the result are the model's
opinion. A method annotated `def follow(self, user_id: int)` when the capture
showed a string id produces code that reads correctly, fails at runtime, and
cannot be checked against the evidence that produced it.

This module is the other path. It infers a client from the same endpoint list,
and every type it writes can be traced to a recorded value:

    from mimic.sources import endpoints
    from mimic.codegen_det import client_source

    print(client_source("api.example.com", endpoints(flows, "api.example.com")))

Three rules, and the third is the one that matters:

- **Only what was observed.** A type comes from a value that was actually in
  the capture — a body field, or a URL segment. Nothing is inferred from what
  the path "probably" means.
- **No evidence, no type.** JSON `null` says a field exists; it does not say
  what the field is when it isn't null. Those are emitted as `Any` and flagged
  ``UNKNOWN``, in the code, next to the name — because a plausible-looking
  wrong type is worse than an admitted gap.
- **The runtime is not reimplemented.** The generated client subclasses
  `mimic.App`, so it inherits retry, cookie rotation, drift detection and the
  transport seam. This module writes method signatures and a shape table; it
  does not write HTTP code.
"""

import re

from .identity import Persona
from .sources import shapes_from_endpoints


#: Shape-fingerprint kind -> Python annotation. `null` has no entry: a field
#: seen only as null has no known type, and `Any` plus a marker says that.
_TYPES = {
    "string": "str",
    "boolean": "bool",
    "number": "Union[int, float]",   # JSON does not say which; `float` would lie
    "object": "dict",
    "array": "list",
}

#: What we write when a field's type was never actually observed.
UNKNOWN_TYPE = "Any"

_UNKNOWN_NOTE = "capture only ever saw this field as null"

_RESERVED = {"class", "def", "return", "import", "from", "lambda", "pass",
             "None", "True", "False", "global", "self"}


# ---- the inferred model ------------------------------------------------------
class Param:
    """One method argument: its name, its type, and how that type was reached."""

    __slots__ = ("name", "type", "evidence", "unknown")

    def __init__(self, name, type_, evidence, unknown=False):
        self.name = name
        self.type = type_
        self.evidence = evidence
        self.unknown = unknown

    @property
    def default(self):
        return " = None" if self.name == "body" else ""

    def __repr__(self):
        return f"<Param {self.name}: {self.type}>"


class Field:
    """One response field, with the fingerprint kind it was recorded under."""

    __slots__ = ("path", "kind")

    def __init__(self, path, kind):
        self.path = path
        self.kind = kind

    @property
    def known(self):
        """False when the capture only ever saw this field as null."""
        return self.kind != "null"

    @property
    def type(self):
        return _TYPES.get(self.kind, UNKNOWN_TYPE)


class Method:
    """One generated method: what it sends, and what it was recorded returning."""

    def __init__(self, name, method, path, params, fields, status,
                 literal_paths, body=None, operation=None,
                 operation_type=None, query="", variables=()):
        self.name = name
        self.method = method
        self.path = path
        self.params = list(params)
        self.fields = list(fields)
        self.status = status
        self.literal_paths = tuple(literal_paths)
        self.body = body
        self.operation = operation
        self.operation_type = operation_type
        self.query = query
        self.variables = tuple(variables)

    @property
    def is_graphql(self):
        return bool(self.operation)

    def __repr__(self):
        return f"<Method {self.name} {self.method} {self.path}>"


class Plan:
    """Everything inferred, before any of it is rendered to text."""

    def __init__(self, class_name, host, methods, shapes, persona=None):
        self.class_name = class_name
        self.host = host
        self.methods = list(methods)
        self.shapes = shapes
        self.persona = persona

    def __repr__(self):
        return f"<Plan {self.class_name} {len(self.methods)} methods>"


# ---- inference ---------------------------------------------------------------
def plan(host, endpoints, class_name=None, persona=None):
    """Infer a client from captured endpoints. Pure — no I/O, no code executed.

    `persona` is optional and is *validated* here, so a contradictory capture is
    refused at generation time by the same rules that refuse it at load time.
    """
    if persona is not None and not isinstance(persona, Persona):
        persona = Persona.from_headers(persona)
    if persona is not None:
        # The same gate the vault applies at load time, applied here too: a
        # contradictory capture should not become a generated file.
        persona.validate()

    methods, taken = [], set()
    for entry in endpoints:
        method = _method(entry, taken)
        taken.add(method.name)
        methods.append(method)
    return Plan(class_name or _class_name(host), host, methods,
                shapes_from_endpoints(endpoints), persona)


def _method(entry, taken):
    path = entry.get("path", "/")
    method = entry.get("method", "GET").upper()
    operation = entry.get("operation")
    name = _unique(_base_name(method, path, operation), taken)
    body = entry.get("request_body") or ""

    params = []
    for param in entry.get("path_params") or []:
        params.append(_param_for(param, entry.get("response_shape") or {}))
    if operation:
        params += [_param_for(v, entry.get("response_shape") or {})
                   for v in entry.get("variables") or ()]
    elif body.strip():
        params.append(Param("body", "dict", "observed request body"))

    fields = [Field(p, k) for p, k in
              sorted((entry.get("response_shape") or {}).items())]
    return Method(
        name=name, method=method, path=path, params=params, fields=fields,
        status=entry.get("status"),
        literal_paths=entry.get("literal_paths") or [path],
        body=body or None, operation=operation,
        operation_type=entry.get("operation_type"),
        query=entry.get("query") or "", variables=entry.get("variables") or (),
    )


def _param_for(name, shape):
    """Type a parameter from a recorded value, or admit that we can't.

    Path parameters and GraphQL variables are both looked up in the captured
    response shape by name. No match means the value was never recorded as a
    typed body field, which is a different — and weaker — claim.
    """
    kind = None
    where = None
    for path, seen in sorted(shape.items()):
        if path.rsplit(".", 1)[-1] == name:
            kind, where = seen, path
            break
    if kind is None:
        return Param(name, "str", "seen only as a URL segment")
    if kind == "null":
        return Param(name, UNKNOWN_TYPE, f"observed at {where}: {_UNKNOWN_NOTE}",
                     unknown=True)
    return Param(name, _TYPES.get(kind, UNKNOWN_TYPE), f"observed at {where} as {kind}")


def _base_name(method, path, operation):
    """A method name derived only from what the capture says."""
    if operation:
        return _unique_prefix(_snake(operation), method)
    parts = [p for p in path.split("/") if p and not p.startswith("{")]
    stem = "_".join([method.lower()] + [_snake(p) for p in parts])
    return _snake(stem) or "root"


def _unique_prefix(stem, method):
    return _snake(f"{method.lower()}_{stem}") or _snake(method.lower())


def _snake(text):
    """camelCase / kebab / dotted -> snake_case, without touching digits.

    Never returns a leading digit. `/2fa/verify` would otherwise render as
    `def 2fa_verify(...)`, which is a syntax error in the file being written —
    and unlike a wrong name, an unimportable one ends the run.
    """
    text = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", str(text))
    text = re.sub(r"[^A-Za-z0-9]+", "_", text).strip("_").lower()
    return f"r{text}" if text[:1].isdigit() else text


def _unique(name, taken):
    candidate, n = name, 1
    while candidate in taken or candidate in _RESERVED:
        n += 1
        candidate = f"{name}_{n}"
    return candidate


def _class_name(host):
    """The client class name, and always a legal one.

    A host whose first label starts with a digit is not exotic: `127.0.0.1` for
    a local dev server, and `10.0.2.2` for the Android emulator. `127Client`
    is a syntax error, so the `Api` fallback covers that as well as an empty
    label.
    """
    label = (host or "api").split(".")[0]
    parts = [p for p in re.split(r"[^A-Za-z0-9]+", label) if p]
    stem = "".join(p[:1].upper() + p[1:] for p in parts)
    if not stem[:1].isalpha():
        stem = f"Api{stem}"
    return f"{stem}Client"


# ---- rendering ---------------------------------------------------------------
def render(plan_):
    """Render a `Plan` to importable Python source."""
    out = [_preamble(plan_)]
    for method in plan_.methods:
        if method.is_graphql and method.query:
            out.append(f"\n{_const_name(method)} = {method.query!r}")
    # Always emitted, even when empty: the class wires it into Session, so a
    # capture with no responses must still generate a client that imports.
    out.append("\n\n" + _shape_table(plan_))
    out.append("\n\n" + _class(plan_))
    return "".join(out)


def client_source(host, endpoints, class_name=None, persona=None):
    """Infer and render in one step. Returns the Python source as a string."""
    return render(plan(host, endpoints, class_name=class_name, persona=persona))


def _preamble(plan_):
    lines = [
        '"""Client generated by mimic from a capture — no AI was involved.',
        "",
        f"Generated from {len(plan_.methods)} captured endpoint"
        f"{'s' if len(plan_.methods) != 1 else ''} on `{plan_.host}`.",
    ]
    if plan_.persona is not None:
        lines += ["", "The capture's identity, checked for coherence when this",
                  "file was written:", "", plan_.persona.describe()]
    lines += [
        "",
        "Every type below is traceable to a value that was actually recorded.",
        "A field marked UNKNOWN was only ever seen as null, so its real type is",
        'genuinely unknown and is left that way rather than guessed.',
    ]
    return "\n".join(lines) + '\n"""\n\nfrom typing import Any, Union\n\nfrom mimic import App\n'


def _const_name(method):
    return "_" + re.sub(r"[^A-Za-z0-9]+", "_", method.operation or "").upper()


def _shape_table(plan_):
    lines = [
        "#: Response shapes recorded at generation time, keyed by\n"
        "#: (method, literal path, GraphQL operation). Handed to Session so a\n"
        "#: field the app stops sending is reported by name — inherit that from\n"
        "#: `mimic` instead of catching a KeyError in your own code.\n"
        "CAPTURED_SHAPES = {",
    ]
    if not plan_.shapes:
        return "CAPTURED_SHAPES = {}"
    for (method, literal, operation), shape in sorted(
            plan_.shapes.items(), key=lambda kv: tuple(map(str, kv[0]))):
        lines.append(f"    ({method!r}, {literal!r}, {operation!r}): {shape!r},")
    lines.append("}")
    return "\n".join(lines)


def _class(plan_):
    lines = [
        f"\nclass {plan_.class_name}(App):",
        f'    """A replay of what `{plan_.host}` was actually seen doing."""\n',
        f'    HOST = {plan_.host!r}\n',
        "    def __init__(self, **kw):",
        "        kw.setdefault(\"shapes\", CAPTURED_SHAPES)",
        "        super().__init__(**kw)\n",
    ]
    for method in plan_.methods:
        lines += _render_method(method)
    return "\n".join(lines)


def _render_method(method):
    args = ", ".join(f"{p.name}: {p.type}{p.default}" for p in method.params)
    doc = _docstring(method)
    indented = "\n".join("        " + line.rstrip()
                         for line in doc.splitlines()[1:])
    doc = doc.splitlines()[0] + ("\n" + indented if indented else "")
    lines = [f"    def {method.name}(self{', ' if args else ''}{args}) -> dict:",
             f'        """{doc}\n        """']
    for param in method.params:
        if param.unknown:
            lines.append(f"        # {param.name}: UNKNOWN — {param.evidence}")
        elif param.evidence.startswith("seen only"):
            lines.append(f"        # {param.name}: {param.evidence}, so str is"
                         f" all that was recorded")
        else:
            lines.append(f"        # {param.name}: {param.evidence}")
    lines.append(_call(method))
    lines.append("")
    return lines


def _docstring(method):
    head = f"{method.method} {method.path} -> {method.status}"
    if method.is_graphql:
        head += f"  [{method.operation_type or 'query'}: {method.operation}]"
    lines = [head]
    if method.literal_paths:
        shown = ", ".join(method.literal_paths[:4])
        lines.append("observed at: " + shown)
    if method.fields:
        lines.append("")
        lines.append("response fields recorded at generation time:")
        width = max(len(f.path) for f in method.fields)
        for field in method.fields:
            if field.known:
                lines.append(f"  {field.path.ljust(width)}  {field.type}")
            else:
                lines.append(f"  {field.path.ljust(width)}  {UNKNOWN_TYPE}"
                             f"  UNKNOWN: {_UNKNOWN_NOTE}")
    return "\n".join(lines)


def _call(method):
    if method.is_graphql:
        const = _const_name(method)
        wire = [f"\"query\": {const}", f"\"operationName\": {method.operation!r}"]
        if method.variables:
            names = ", ".join(f"{v!r}: {v}" for v in method.variables)
            wire.append(f"\"variables\": {{{names}}}")
        return (f"        return self.post({method.path!r}, "
                f"{{{', '.join(wire)}}})")
    return f"        return {_path_expr(method)}"


def _path_expr(method):
    """The call that sends this task: an f-string for a templated path, plus the
    request body when the capture showed one."""
    path = method.path
    rendered = f"f{path!r}" if "{" in path else repr(path)
    args = [rendered]
    if any(p.name == "body" for p in method.params):
        args.append("body")
    return f"self.{method.method.lower()}({', '.join(args)})"


__all__ = ["client_source", "plan", "render", "Plan", "Method", "Param", "Field"]
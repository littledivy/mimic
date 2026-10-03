"""Backend-neutral helpers over mimic's flow dicts.

Both capture backends normalize into the same shape, so host counting, body
decoding, endpoint extraction and shape fingerprinting live here rather than
being written once per backend.

A flow dict looks like this::

    {"id": ...,
     "request":  {"host", "method", "path", "scheme", "port", "headers",
                  "content": b"..."},
     "response": {"status_code", "headers", "content": b"..."}}

`content` is present only when the backend captured bodies. Endpoint extraction
reads whatever is there and treats an absent body as empty, so a caller holding
lightweight flows still gets structure — just no bodies to show.
"""
import gzip
import json
import re
import zlib

from ..graphql import parse as parse_graphql
from ..shapes import shape_of

BODY_LIMIT = 4000

#: A path segment that is an identifier rather than a route: a number or a UUID.
#: Used to *group* samples of the same endpoint; a segment only becomes a
#: template parameter if it actually varies, so `/v2/users` keeps its "v2".
_IDENTIFIER_SEGMENT = re.compile(
    r"^(?:\d+|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$"
)


def decode_body(raw, limit=BODY_LIMIT):
    """Decode a body to a truncated JSON/text string for codegen to read."""
    if not raw:
        return ""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return f"<{len(raw)} bytes binary>"
    try:  # pretty-print so the reader sees structure, not a single long line
        text = json.dumps(json.loads(text), indent=2)
    except ValueError:
        pass
    return text[:limit] + ("\n…(truncated)" if len(text) > limit else "")


def _content_encoding(headers):
    """The `Content-Encoding` value, whichever shape the headers came in.

    Backends hand us header pairs, but a plain mapping is a natural thing for a
    caller to pass, and silently decoding nothing because of it would be a
    quiet failure.
    """
    if not headers:
        return ""
    if isinstance(headers, dict):
        headers = headers.items()
    for name, value in headers:
        if str(name).lower() == "content-encoding":
            return (value or "").split(",")[0].strip().lower()
    return ""


def decompress(raw, headers):
    """Undo `Content-Encoding` so a compressed body parses like a plain one.

    Skipping this is worse than it sounds: a gzipped body decodes to bytes that
    aren't UTF-8, so the GraphQL reader finds no operation and no response shape
    is recorded — and both failures are silent.
    """
    if not raw:
        return raw
    encoding = _content_encoding(headers)
    try:
        if encoding in ("gzip", "x-gzip"):
            return gzip.decompress(raw)
        if encoding == "deflate":
            try:
                return zlib.decompress(raw)
            except zlib.error:
                return zlib.decompress(raw, -zlib.MAX_WBITS)  # headerless
        if encoding == "br":
            import brotli  # optional; not stdlib

            return brotli.decompress(raw)
    except Exception:
        # Already decompressed, corrupt, or an encoding we can't undo. The
        # caller's decoder handles plain bytes, so degrade rather than raise.
        return raw
    return raw


def hosts(flows):
    """Count requests per host, most frequent first."""
    counts = {}
    for f in flows:
        req = f.get("request")
        if req:
            counts[req["host"]] = counts.get(req["host"], 0) + 1
    return sorted(counts.items(), key=lambda kv: -kv[1])


#: Distinguishes "this body isn't JSON" from "this body is JSON null", which
#: a bare `None` return would collapse together — and a null body would then be
#: fingerprinted as an object and flagged as drift against itself.
_MISSING = object()


def _json(raw):
    """Parse a body as JSON, or return _MISSING if it isn't JSON."""
    if not raw:
        return _MISSING
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return _MISSING


def _shape_key(path):
    """A path with identifier-shaped segments blanked out, for grouping.

    The query string is dropped first: `/users?page=1` and `/users?page=2` are
    one endpoint, and keying on the query would split them.
    """
    path = path.split("?")[0]
    return "/".join(
        "{}" if _IDENTIFIER_SEGMENT.match(s) else s
        for s in path.strip("/").split("/")
    )


def _values_for(blob, needle, out):
    """Collect field names whose value equals `needle`, at any depth.

    Compared as strings: a path segment is always text, but the id in the JSON
    body that names it is usually a number, and `8931 == "8931"` is False.
    """
    if isinstance(blob, dict):
        for key, value in blob.items():
            if not isinstance(value, (dict, list)) and str(value) == needle:
                out.append(key)
            _values_for(value, needle, out)
    elif isinstance(blob, list):
        for item in blob:
            _values_for(item, needle, out)
    return out


def _param_name(values, blobs, fallback_index):
    """Name a path parameter after the field that supplies its value.

    Matching the observed value against the request and response bodies turns
    `/users/8931` into `/users/{user_id}` rather than `/users/{id}` or, worse,
    `/users/{param0}` — the name a generated client actually needs.
    """
    candidates = []
    for value in values:
        for blob in blobs:
            _values_for(blob, value, candidates)
    # A field named for the thing itself ("id" on a user resource) is the most
    # informative; a generic "id" is not, so deprioritise it.
    specific = [c for c in candidates if str(c).lower() not in ("id", "ids", "pk")]
    chosen = (specific or candidates)
    if not chosen:
        return f"param{fallback_index}"
    name = chosen[0]
    cleaned = re.sub(r"(?<!^)(?=[A-Z])", "_", str(name)).lower()
    cleaned = re.sub(r"[^a-z0-9_]+", "_", cleaned).strip("_")
    return cleaned or f"param{fallback_index}"


def _templatize(samples, blobs=()):
    """Turn the concrete paths of `samples` into one parameterised path.

    A position becomes a parameter only when it actually varies, so `/v2/users`
    and `/api/health` are left alone while `/users/8931` and `/users/8932`
    collapse to `/users/{user_id}`.
    """
    concrete = [p.strip("/").split("/") for p in samples]
    shape_parts = _shape_key(samples[0]).strip("/").split("/")
    if len({len(c) for c in concrete}) > 1:
        return samples[-1], []  # differing depths: not one shape

    names, params = [], []
    for position, is_identifier in enumerate(shape_parts):
        column = [parts[position] for parts in concrete]
        if is_identifier == "{}" and len(set(column)) > 1:
            name = _param_name(column, blobs, len(params))
            names.append("{" + name + "}")
            params.append(name)
        else:
            names.append(column[0])
    return "/" + "/".join(names), params


def endpoints(flows, host):
    """Distinct endpoints for a host, with a sample request/response body.

    Returns a list of dicts ready to feed to codegen. Latest capture of each
    endpoint wins, so bodies reflect the most recent real call.

    Three things keep endpoints distinguishable instead of collapsing:

    - GraphQL is keyed by operation name, not URL, because every operation in a
      GraphQL app shares one path.
    - Paths are templated, so `/users/8931` and `/users/8932` are one endpoint
      with `path_params` naming what varies.
    - Each entry records the literal paths it was seen at, so drift detection
      can still look a live request up by its real path.

    Pure: bodies come from the flows, so this does no I/O.
    """
    grouped = {}
    for f in flows:
        req = f.get("request")
        if not req or req["host"] != host:
            continue
        raw_path = req.get("path", "")
        body = _json(decompress(req.get("content"), req.get("headers")))
        gql = parse_graphql(None if body is _MISSING else body)
        key = (req["method"], _shape_key(raw_path),
               gql["operation"] if gql else None)
        grouped.setdefault(key, {"flows": [], "gql": gql})
        grouped[key]["flows"].append(f)

    out = []
    for (method, _, operation), group in grouped.items():
        samples = group["flows"]
        latest = samples[-1]
        req = latest.get("request") or {}
        resp = latest.get("response") or {}
        literal_paths, blobs = [], []
        for f in samples:
            r = f.get("request") or {}
            literal_paths.append(r.get("path", "").split("?")[0])
            blobs.append(_json(decompress(r.get("content"), r.get("headers"))))
            blobs.append(_json(decompress((f.get("response") or {}).get("content"),
                                          (f.get("response") or {}).get("headers"))))

        path, params = _templatize(literal_paths, blobs)
        parsed = _json(decompress(resp.get("content"), resp.get("headers")))
        raw_path = req.get("path", "")
        entry = {
            "method": method,
            "path": path,
            "literal_paths": sorted(set(literal_paths)),
            "path_params": params,
            "status": resp.get("status_code"),
            "query": raw_path.split("?", 1)[1] if "?" in raw_path else "",
            "request_body": decode_body(decompress(req.get("content"),
                                                   req.get("headers"))),
            "response_body": decode_body(decompress(resp.get("content"),
                                                    resp.get("headers"))),
            "response_shape": {} if parsed is _MISSING else shape_of(parsed),
        }
        if group["gql"]:
            entry.update(group["gql"])
        out.append(entry)
    return out


def shapes(flows, host):
    """Map every endpoint's key to its captured response shape.

    Feed the result to `Session(shapes=...)` to get drift detection on live
    responses. Keys are ``(method, literal path, operation)`` — the *literal*
    paths, because a Session looks a live request up by the path it actually
    requested, not by a template.
    """
    return shapes_from_endpoints(endpoints(flows, host))


def shapes_from_endpoints(eps):
    """The same map, from an endpoint list you already have.

    Split out so a caller that has just built the endpoint list — the
    deterministic generator, mostly — does not have to go back to the flows and
    rebuild it to get the same answer.
    """
    out = {}
    for e in eps:
        if not e["response_shape"]:
            continue
        for literal in e["literal_paths"] or [e["path"]]:
            out[(e["method"], literal, e.get("operation"))] = e["response_shape"]
    return out

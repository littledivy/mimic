"""Read captured traffic from a running mitmweb instance.

mitmweb exposes a JSON API on http://127.0.0.1:8081. Auth is a bearer token sent
once to establish a session cookie; subsequent requests reuse the cookie. This
module pulls the raw flows and normalizes them into a shape that both the
runtime Session and the AI codegen step can consume.
"""
import json
import os
import re
from urllib.parse import parse_qsl, unquote, urlsplit

import requests

from .. import proxy


DEFAULT_URL = "http://127.0.0.1:8081"
DEFAULT_MAX_SAMPLES_PER_ENDPOINT = 5
MAX_SCHEMA_DEPTH = 8
MAX_SCHEMA_PROPERTIES = 128

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.I,
)
_ULID_RE = re.compile(r"^[0-9A-HJKMNP-TV-Z]{26}$", re.I)
_HEX_ID_RE = re.compile(r"^(?:[0-9a-f]{24}|[0-9a-f]{32,})$", re.I)
_VERSION_RE = re.compile(r"^(?:v\d+(?:\.\d+)*|api[-_]?v?\d+)$", re.I)
_DATE_RE = re.compile(r"^(?:19|20)\d{2}(?:-\d{2}(?:-\d{2})?)?$")
_COMPACT_DATE_RE = re.compile(r"^(?:19|20)\d{6}$")
_FILENAME_RE = re.compile(r"^.+\.[a-z0-9]{1,8}$", re.I)

_PROTECTED_ALIASES = {"me", "my", "current", "latest", "self", "default"}
_PROTECTED_NUMBER_CONTEXTS = {
    "api", "code", "day", "format", "height", "limit", "month", "offset",
    "page", "schema", "size", "status", "version", "width", "year",
}
_RESOURCE_NAMES = {
    "account", "accounts", "comment", "comments", "conversation",
    "conversations", "device", "devices", "item", "items", "message",
    "messages", "order", "orders", "player", "players", "post", "posts",
    "profile", "profiles", "session", "sessions", "thread", "threads",
    "user", "users",
}
_TELEMETRY_HOST_SUFFIXES = (
    "amplitude.com", "app-measurement.com", "browser-intake-datadoghq.com",
    "datadoghq.com", "google-analytics.com", "ingest.sentry.io",
    "mixpanel.com", "nr-data.net", "segment.io",
)
_TELEMETRY_HEADERS = (
    "x-amplitude-", "x-datadog-", "x-segment-", "x-sentry-auth",
)
_TELEMETRY_SEGMENTS = {
    "analytics", "beacon", "beacons", "client-logs", "client_logs",
    "crash-report", "crash-reports", "crash_report", "crash_reports",
    "diagnostics", "metrics", "rum", "spans", "telemetry", "traces",
}


class MitmError(RuntimeError):
    pass


class Mitm:
    """A thin client over a running mitmweb's flow API."""

    def __init__(self, url=None, token=None):
        state = proxy.load_state() or {}
        configured_url = url or os.environ.get("MITM_URL")
        env_token = os.environ.get("MITM_TOKEN")
        if configured_url:
            # Never send a token loaded for mimic's local proxy to an unrelated
            # explicitly configured URL.
            self.url = configured_url.rstrip("/")
            self.token = token if token is not None else env_token
        else:
            self.url = (state.get("url") or DEFAULT_URL).rstrip("/")
            self.token = (
                token
                if token is not None
                else env_token or state.get("token")
            )
        self._http = requests.Session()

    def _auth(self):
        try:
            headers = (
                {"Authorization": f"Bearer {self.token}"} if self.token else {}
            )
            r = self._http.get(f"{self.url}/", headers=headers, timeout=5)
        except requests.RequestException as e:
            raise MitmError(
                f"can't reach mitmweb at {self.url} — is it running? "
                f"start it with `mimic record` (original error: {e})"
            )
        if r.status_code != 200:
            raise MitmError(
                f"mitmweb authentication failed with {r.status_code} — "
                "start it with `mimic record`, or set MITM_TOKEN for a "
                "manually managed proxy"
            )

    def flows(self):
        """All captured flows as a list of dicts (mitmweb's own schema)."""
        self._auth()
        r = self._http.get(f"{self.url}/flows", timeout=15)
        if r.status_code != 200:
            raise MitmError(f"mitmweb /flows returned {r.status_code}")
        return r.json()

    def body(self, flow_id, side):
        """Raw request/response body bytes for a flow. side is 'request' or 'response'."""
        r = self._http.get(
            f"{self.url}/flows/{flow_id}/{side}/content.data", timeout=15
        )
        if r.status_code != 200:
            raise MitmError(f"mitmweb flow body returned {r.status_code}")
        return r.content

    def clear(self):
        """Permanently remove all in-memory flows and events from mitmweb."""
        self._auth()
        xsrf = self._http.cookies.get("_mitmproxy_xsrf") or self._http.cookies.get(
            "_xsrf"
        )
        headers = {"X-XSRFToken": xsrf} if xsrf else {}
        r = self._http.post(f"{self.url}/clear", headers=headers, timeout=15)
        if r.status_code not in (200, 204):
            raise MitmError(f"mitmweb /clear returned {r.status_code}")


def _headers_dict(message):
    return {str(k).lower(): str(v) for k, v in message.get("headers", [])}


def hosts(flows):
    """Count requests per host, most frequent first."""
    counts = {}
    for f in flows:
        req = f.get("request")
        if req:
            counts[req["host"]] = counts.get(req["host"], 0) + 1
    return sorted(counts.items(), key=lambda kv: -kv[1])


def endpoints(
    mitm,
    flows,
    host,
    *,
    include_bodies=True,
    include_telemetry=False,
    max_samples=DEFAULT_MAX_SAMPLES_PER_ENDPOINT,
):
    """Normalize captured flows into bounded, multi-sample endpoint records."""
    metadata = []
    for index, flow in enumerate(flows):
        req = flow.get("request")
        if not req or req.get("host") != host:
            continue
        meta = _flow_metadata(flow, index)
        if not include_telemetry and _is_telemetry(meta):
            continue
        metadata.append(meta)

    varying_numbers = _varying_numeric_positions(metadata)
    groups = {}
    for meta in metadata:
        template = _normalize_path(meta, varying_numbers)
        meta["template"] = template
        groups.setdefault((meta["method"], template), []).append(meta)

    out = []
    for (method, path), samples in sorted(
        groups.items(), key=lambda item: (item[0][1], item[0][0])
    ):
        selected = _select_samples(samples, max_samples)
        hydrated = [
            _hydrate_sample(mitm, sample) if include_bodies else _plain_sample(sample)
            for sample in selected
        ]
        primary = hydrated[0]
        statuses = sorted(
            {sample["status"] for sample in samples if sample["status"] is not None}
        )
        schemas = _schemas(hydrated) if include_bodies else {}
        out.append(
            {
                "method": method,
                "path": path,
                "status": primary["status"],
                "query": primary["query"],
                "request_body": primary["request_body"],
                "response_body": primary["response_body"],
                "sample_count": len(samples),
                "schema_sample_count": len(hydrated) if include_bodies else 0,
                "raw_paths": sorted({sample["path"] for sample in samples}),
                "statuses": statuses,
                "samples": hydrated,
                "schemas": schemas,
            }
        )
    return out


def _flow_metadata(flow, index):
    req = flow.get("request") or {}
    resp = flow.get("response") or {}
    split = urlsplit(req.get("path") or "/")
    request_headers = _headers_dict(req)
    response_headers = _headers_dict(resp)
    return {
        "flow": flow,
        "id": flow.get("id") or str(index),
        "index": index,
        "method": (req.get("method") or "GET").upper(),
        "host": req.get("host") or "",
        "path": split.path or "/",
        "query": split.query,
        "query_keys": tuple(sorted({k for k, _ in parse_qsl(split.query, keep_blank_values=True)})),
        "status": resp.get("status_code"),
        "request_headers": request_headers,
        "response_headers": response_headers,
        "request_content_type": request_headers.get("content-type", "").split(";", 1)[0],
        "response_content_type": response_headers.get("content-type", "").split(";", 1)[0],
        "recency": _recency(flow, index),
    }


def _recency(flow, index):
    for message, key in (
        (flow.get("response") or {}, "timestamp_end"),
        (flow.get("request") or {}, "timestamp_start"),
        (flow, "timestamp_created"),
    ):
        try:
            return (float(message[key]), index)
        except (KeyError, TypeError, ValueError):
            pass
    return (float(index), index)


def _is_telemetry(meta):
    host = meta["host"].lower().rstrip(".")
    if any(host == suffix or host.endswith("." + suffix) for suffix in _TELEMETRY_HOST_SUFFIXES):
        return True

    header_names = tuple(meta["request_headers"])
    if any(
        name == marker or name.startswith(marker)
        for name in header_names
        for marker in _TELEMETRY_HEADERS
    ):
        return True

    if meta["method"] not in {"POST", "PUT", "PATCH"}:
        return False
    segments = {unquote(part).lower() for part in meta["path"].split("/") if part}
    return bool(segments & _TELEMETRY_SEGMENTS)


def _varying_numeric_positions(metadata):
    buckets = {}
    for meta in metadata:
        parts = _path_parts(meta["path"])
        signature = []
        number_positions = []
        for index, part in enumerate(parts):
            previous = parts[index - 1] if index else ""
            if _high_confidence_id(part, previous):
                signature.append("{id}")
            elif part.isdigit() and not _protected_segment(part, previous):
                signature.append("{number}")
                number_positions.append(index)
            else:
                signature.append(part)
        key = (meta["method"], tuple(signature))
        buckets.setdefault(key, []).append((meta, parts, number_positions))

    varying = set()
    for (method, signature), entries in buckets.items():
        if len(entries) < 2:
            continue
        for position, marker in enumerate(signature):
            if marker != "{number}":
                continue
            values = {parts[position] for _, parts, _ in entries}
            if len(values) > 1:
                varying.add((method, signature, position))
    return varying


def _normalize_path(meta, varying_numbers):
    parts = _path_parts(meta["path"])
    signature = []
    for index, part in enumerate(parts):
        previous = parts[index - 1] if index else ""
        if _high_confidence_id(part, previous):
            signature.append("{id}")
        elif part.isdigit() and not _protected_segment(part, previous):
            signature.append("{number}")
        else:
            signature.append(part)

    names = {}
    normalized = []
    for index, part in enumerate(parts):
        previous = parts[index - 1] if index else ""
        is_id = _high_confidence_id(part, previous)
        if part.isdigit() and not _protected_segment(part, previous):
            key = (meta["method"], tuple(signature), index)
            is_id = key in varying_numbers or _resource_like(previous)
        if not is_id:
            normalized.append(part)
            continue
        name = _placeholder_name(previous, names)
        normalized.append("{" + name + "}")

    path = "/" + "/".join(normalized)
    if meta["path"].endswith("/") and path != "/":
        path += "/"
    return path


def _path_parts(path):
    return [part for part in path.strip("/").split("/") if part]


def _protected_segment(segment, previous=""):
    decoded = unquote(segment)
    lower = decoded.lower()
    previous = unquote(previous).lower()
    return (
        lower in _PROTECTED_ALIASES
        or bool(_VERSION_RE.match(lower))
        or bool(_DATE_RE.match(lower))
        or bool(_COMPACT_DATE_RE.match(lower))
        or bool(_FILENAME_RE.match(lower))
        or previous in _PROTECTED_NUMBER_CONTEXTS
    )


def _high_confidence_id(segment, previous=""):
    decoded = unquote(segment)
    if _protected_segment(decoded, previous):
        return False
    if _UUID_RE.match(decoded) or _ULID_RE.match(decoded) or _HEX_ID_RE.match(decoded):
        return True
    if decoded.isdigit() and len(decoded) >= 6:
        return True
    return (
        len(decoded) >= 16
        and decoded.isalnum()
        and any(char.isalpha() for char in decoded)
        and any(char.isdigit() for char in decoded)
    )


def _resource_like(segment):
    lower = unquote(segment).lower()
    return lower in _RESOURCE_NAMES


def _placeholder_name(previous, names):
    base = re.sub(r"[^a-z0-9]+", "_", unquote(previous).lower()).strip("_")
    if base.endswith("ies") and len(base) > 3:
        base = base[:-3] + "y"
    elif base.endswith("s") and not base.endswith("ss") and len(base) > 3:
        base = base[:-1]
    base = (base or "path") + "_id"
    count = names.get(base, 0) + 1
    names[base] = count
    return base if count == 1 else f"{base}_{count}"


def _select_samples(samples, limit):
    if limit < 1:
        raise ValueError("max_samples must be at least 1")
    newest = sorted(samples, key=lambda sample: sample["recency"], reverse=True)
    primary = next(
        (sample for sample in newest if sample["status"] and 200 <= sample["status"] < 300),
        next((sample for sample in newest if sample["status"] is not None), newest[0]),
    )
    selected = [primary]
    seen = {_diversity_key(primary)}
    for sample in newest:
        if sample is primary:
            continue
        key = _diversity_key(sample)
        if key not in seen:
            selected.append(sample)
            seen.add(key)
        if len(selected) == limit:
            return selected
    for sample in newest:
        if sample not in selected:
            selected.append(sample)
        if len(selected) == limit:
            break
    return selected


def _diversity_key(sample):
    return (
        _status_class(sample["status"]),
        sample["query_keys"],
        sample["request_content_type"],
        sample["response_content_type"],
    )


def _status_class(status):
    return f"{status // 100}xx" if isinstance(status, int) else "unknown"


def _plain_sample(meta):
    return {
        "path": meta["path"],
        "query": meta["query"],
        "status": meta["status"],
        "request": {"kind": "empty", "size_bytes": 0},
        "response": {"kind": "empty", "size_bytes": 0},
        "request_body": "",
        "response_body": "",
    }


def _hydrate_sample(mitm, meta):
    req = meta["flow"].get("request") or {}
    resp = meta["flow"].get("response")
    request_body = (
        _parse_body(mitm.body(meta["id"], "request"))
        if _may_have_body(req)
        else {"kind": "empty", "size_bytes": 0}
    )
    response_body = (
        _parse_body(mitm.body(meta["id"], "response"))
        if resp and _may_have_body(resp)
        else {"kind": "empty", "size_bytes": 0}
    )
    return {
        "path": meta["path"],
        "query": meta["query"],
        "status": meta["status"],
        "request": request_body,
        "response": response_body,
        "request_body": _body_text(request_body),
        "response_body": _body_text(response_body),
    }


def _may_have_body(message):
    for key in ("contentLength", "content_length"):
        if key in message:
            try:
                return int(message[key]) != 0
            except (TypeError, ValueError):
                break
    length = _headers_dict(message).get("content-length")
    if length is not None:
        try:
            return int(length) != 0
        except ValueError:
            pass
    return True


def _parse_body(raw):
    if not raw:
        return {"kind": "empty", "size_bytes": 0}
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return {"kind": "binary", "size_bytes": len(raw)}
    try:
        value = json.loads(text)
    except ValueError:
        return {"kind": "text", "size_bytes": len(raw), "text": text}
    return {"kind": "json", "size_bytes": len(raw), "value": value}


def _body_text(body):
    if body["kind"] == "json":
        return json.dumps(body["value"], indent=2, ensure_ascii=False, sort_keys=True)
    if body["kind"] == "text":
        return body["text"]
    if body["kind"] == "binary":
        return f"<{body['size_bytes']} bytes binary>"
    return ""


def _decode(raw, limit=None):
    """Best-effort body decoding retained for callers outside endpoint extraction."""
    text = _body_text(_parse_body(raw))
    if limit is None or len(text) <= limit:
        return text
    return text[:limit] + "\n…(truncated)"


def _schemas(samples):
    request_values = [
        sample["request"]["value"]
        for sample in samples
        if sample["request"]["kind"] == "json"
    ]
    responses = {}
    for sample in samples:
        if sample["response"]["kind"] != "json":
            continue
        responses.setdefault(_status_class(sample["status"]), []).append(
            sample["response"]["value"]
        )
    result = {}
    if request_values:
        result["request"] = _infer_schema(request_values)
    if responses:
        result["responses"] = {
            status: _infer_schema(values) for status, values in sorted(responses.items())
        }
    return result


def _infer_schema(values, depth=0):
    if depth >= MAX_SCHEMA_DEPTH:
        return {"x-mimic-truncated": True}

    kinds = {_value_kind(value) for value in values}
    if kinds <= {"integer", "number"}:
        return {"type": "number" if "number" in kinds else "integer"}
    if kinds <= {"null", "boolean", "integer", "number", "string"}:
        scalar_types = set(kinds)
        if "number" in scalar_types:
            scalar_types.discard("integer")
        ordered = [kind for kind in _TYPE_ORDER if kind in scalar_types]
        return {"type": ordered[0] if len(ordered) == 1 else ordered}
    if kinds == {"object"}:
        return _object_schema(values, depth)
    if kinds == {"array"}:
        elements = [item for value in values for item in value]
        return {
            "type": "array",
            "items": _infer_schema(elements, depth + 1) if elements else {},
        }

    variants = []
    grouped = {}
    for value in values:
        kind = _value_kind(value)
        if kind in {"integer", "number"}:
            kind = "number"
        grouped.setdefault(kind, []).append(value)
    for kind in _TYPE_ORDER:
        if kind in grouped:
            variants.append(_infer_schema(grouped[kind], depth + 1))
    return {"anyOf": variants}


_TYPE_ORDER = ("null", "boolean", "integer", "number", "string", "array", "object")


def _value_kind(value):
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return "string"


def _object_schema(values, depth):
    keys = sorted({key for value in values for key in value})
    included = keys[:MAX_SCHEMA_PROPERTIES]
    properties = {}
    required = []
    for key in included:
        present = [value[key] for value in values if key in value]
        properties[key] = _infer_schema(present, depth + 1)
        if len(present) == len(values):
            required.append(key)
    schema = {"type": "object", "properties": properties}
    if required:
        schema["required"] = required
    if len(keys) > len(included):
        schema["x-mimic-truncated"] = True
        schema["x-mimic-omitted-properties"] = len(keys) - len(included)
    return schema

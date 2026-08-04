"""Versioned JSON-lines control plane for agent integrations.

The transport deliberately keeps credentials and replay drafts inside this
process. Model-visible messages receive only policy-filtered tools, bounded
results, and the secret-minimized audit records produced by ``AgentSession``.
"""
from dataclasses import asdict
import hashlib
import json
import re
import secrets

from .agent import AgentPolicyError, AgentSession
from .session import ScopeViolation


PROTOCOL = "mimic-agent/1"
DEFAULT_MAX_LINE_BYTES = 64 * 1024
DEFAULT_MAX_OUTPUT_BYTES = 64 * 1024
DEFAULT_MAX_COLLECTION_ITEMS = 128
DEFAULT_MAX_STRING_BYTES = 8 * 1024

_SENSITIVE_KEY = re.compile(
    r"(?:^|[-_])(?:authorization|cookie|credential|password|passwd|secret|"
    r"session|token|api[-_]?key|private[-_]?key)(?:$|[-_])",
    re.I,
)
_BEARER = re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]+", re.I)
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")


class ControlProtocolError(ValueError):
    """A malformed or unsupported control-plane message."""


class ControlPlane:
    """Dispatch JSON-safe discovery, request, history, and replay operations."""

    def __init__(
        self,
        agent,
        endpoints=(),
        *,
        mutation_approval_token=None,
        max_output_bytes=DEFAULT_MAX_OUTPUT_BYTES,
    ):
        if not isinstance(agent, AgentSession):
            raise TypeError("agent must be a mimic.AgentSession")
        if max_output_bytes < 1024:
            raise ValueError("max_output_bytes must be at least 1024")
        self.agent = agent
        self.endpoints = tuple(endpoints)
        self.mutation_approval_token = mutation_approval_token
        self.max_output_bytes = max_output_bytes
        self._replay = {}

    def handle(self, message):
        """Handle one decoded request and return a versioned response object."""
        request_id = message.get("id") if isinstance(message, dict) else None
        try:
            payload = self._dispatch(message)
            return {
                "protocol": PROTOCOL,
                "id": request_id,
                "ok": True,
                **payload,
            }
        except Exception as error:
            return {
                "protocol": PROTOCOL,
                "id": request_id,
                "ok": False,
                "error": _safe_error(error),
            }

    def _dispatch(self, message):
        if not isinstance(message, dict):
            raise ControlProtocolError("message must be a JSON object")
        requested_protocol = message.get("protocol", PROTOCOL)
        if requested_protocol != PROTOCOL:
            raise ControlProtocolError(f"unsupported protocol {requested_protocol!r}")
        operation = message.get("op")
        if operation == "tools":
            return {"tools": self.agent.tool_catalog(self.endpoints)}
        if operation == "history":
            return {"history": [asdict(action) for action in self.agent.audit_log]}
        if operation == "request":
            return self._request(message)
        if operation == "replay":
            return self._replay_request(message)
        raise ControlProtocolError("op must be one of: tools, request, history, replay")

    def _request(self, message, *, replayed_from=None):
        method = str(message.get("method", "")).upper()
        path = message.get("path")
        json_body = message.get("json_body")
        params = message.get("params")
        approved = self._mutation_approved(method, message.get("approval_token"))
        before = len(self.agent.audit_log)
        try:
            result = self.agent.request(
                method,
                path,
                json_body=json_body,
                params=params,
                approved=approved,
            )
        finally:
            after = self.agent.audit_log
            if len(after) > before:
                sequence = after[-1].sequence
                self._replay[sequence] = {
                    "method": method,
                    "path": path,
                    "json_body": json_body,
                    "params": params,
                }
        action = asdict(self.agent.audit_log[-1])
        payload = {
            "action": action,
            "result": _bounded_result(result, self.max_output_bytes),
        }
        if replayed_from is not None:
            payload["replayed_from"] = replayed_from
        return payload

    def _replay_request(self, message):
        try:
            sequence = int(message.get("sequence"))
        except (TypeError, ValueError) as error:
            raise ControlProtocolError("replay sequence must be an integer") from error
        original = self._replay.get(sequence)
        if not original:
            raise ControlProtocolError(f"no replayable request for sequence {sequence}")
        replay = dict(original)
        for key in ("json_body", "params"):
            if key in message:
                replay[key] = message[key]
        replay["approval_token"] = message.get("approval_token")
        return self._request(replay, replayed_from=sequence)

    def _mutation_approved(self, method, supplied):
        if method not in {"POST", "PUT", "PATCH", "DELETE"}:
            return False
        expected = self.mutation_approval_token
        if not expected or not supplied:
            return False
        return secrets.compare_digest(str(expected), str(supplied))


def run_jsonl(control, source, sink, *, max_line_bytes=DEFAULT_MAX_LINE_BYTES):
    """Serve newline-delimited JSON until EOF, returning one response per line."""
    for raw_line in source:
        if len(raw_line.encode("utf-8")) > max_line_bytes:
            response = _error_response(None, "message exceeds control-plane byte limit")
        else:
            try:
                message = json.loads(raw_line)
            except (TypeError, ValueError):
                response = _error_response(None, "message is not valid JSON")
            else:
                response = control.handle(message)
        sink.write(json.dumps(response, ensure_ascii=False, sort_keys=True) + "\n")
        sink.flush()


def _bounded_result(value, max_bytes):
    sanitized = _sanitize(value)
    rendered = json.dumps(
        sanitized, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    if len(rendered) <= max_bytes:
        return sanitized
    return {
        "omitted": "sanitized result exceeds control-plane byte limit",
        "size_bytes": len(rendered),
        "sha256": hashlib.sha256(rendered).hexdigest(),
    }


def _sanitize(value, depth=0):
    if depth >= 12:
        return "[TRUNCATED: maximum depth]"
    if isinstance(value, dict):
        result = {}
        items = list(value.items())
        for key, item in items[:DEFAULT_MAX_COLLECTION_ITEMS]:
            key = str(key)
            result[key] = (
                "[REDACTED]" if _SENSITIVE_KEY.search(key) else _sanitize(item, depth + 1)
            )
        if len(items) > DEFAULT_MAX_COLLECTION_ITEMS:
            result["_mimic_omitted_items"] = len(items) - DEFAULT_MAX_COLLECTION_ITEMS
        return result
    if isinstance(value, (list, tuple)):
        items = [_sanitize(item, depth + 1) for item in value[:DEFAULT_MAX_COLLECTION_ITEMS]]
        if len(value) > DEFAULT_MAX_COLLECTION_ITEMS:
            items.append({"_mimic_omitted_items": len(value) - DEFAULT_MAX_COLLECTION_ITEMS})
        return items
    if isinstance(value, str):
        value = _BEARER.sub("Bearer [REDACTED]", value)
        value = _JWT.sub("[REDACTED JWT]", value)
        return _clip(value, DEFAULT_MAX_STRING_BYTES)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return _clip(str(value), DEFAULT_MAX_STRING_BYTES)


def _clip(value, max_bytes):
    raw = value.encode("utf-8")
    if len(raw) <= max_bytes:
        return value
    suffix = f"…[truncated from {len(raw)} bytes]"
    clipped = raw[: max_bytes - len(suffix.encode("utf-8"))]
    return clipped.decode("utf-8", errors="ignore") + suffix


def _safe_error(error):
    if isinstance(error, (ControlProtocolError, AgentPolicyError, ScopeViolation)):
        message = str(error)
    else:
        message = "request failed inside the scoped executor"
    return {"code": type(error).__name__, "message": _sanitize(message)}


def _error_response(request_id, message):
    return {
        "protocol": PROTOCOL,
        "id": request_id,
        "ok": False,
        "error": {"code": "ControlProtocolError", "message": message},
    }

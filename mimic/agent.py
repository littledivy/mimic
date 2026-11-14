"""Policy-enforced, structured access to captured applications for AI agents.

The agent layer intentionally wraps :class:`mimic.Session` instead of exposing
raw captured credentials or an unrestricted HTTP client. It provides a small
authorization boundary today and a stable place for future MCP/JSON-RPC tools.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import re
from urllib.parse import parse_qsl, urlsplit

from .session import Session


READ_ONLY_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
HTTP_METHODS = READ_ONLY_METHODS | MUTATING_METHODS


class AgentPolicyError(RuntimeError):
    """Base error for an agent action rejected before network access."""


class ApprovalRequired(AgentPolicyError):
    """A state-changing action needs an explicit, per-call approval."""


class RequestBudgetExceeded(AgentPolicyError):
    """The agent has consumed its configured request allowance."""


@dataclass(frozen=True)
class AgentPolicy:
    """Capabilities granted to one agent-facing session.

    The default is deliberately read-only. Callers must explicitly grant
    mutating methods, and each mutating request still requires ``approved=True``.
    """

    allowed_methods: frozenset = field(default_factory=lambda: READ_ONLY_METHODS)
    path_prefixes: tuple = ("/",)
    request_budget: int = 100
    require_mutation_approval: bool = True

    def __post_init__(self):
        methods = frozenset(str(method).upper() for method in self.allowed_methods)
        unknown = methods - HTTP_METHODS
        if unknown:
            raise ValueError(f"unsupported HTTP methods: {', '.join(sorted(unknown))}")
        if self.request_budget < 1:
            raise ValueError("request_budget must be positive")
        prefixes = tuple(_normalize_prefix(prefix) for prefix in self.path_prefixes)
        if not prefixes:
            raise ValueError("at least one path prefix is required")
        object.__setattr__(self, "allowed_methods", methods)
        object.__setattr__(self, "path_prefixes", prefixes)

    @classmethod
    def read_write(cls, **kwargs):
        """Create a policy that grants common methods with write approval."""
        return cls(allowed_methods=HTTP_METHODS, **kwargs)


@dataclass(frozen=True)
class AgentAction:
    """Secret-minimized evidence for one attempted network action."""

    sequence: int
    timestamp: str
    method: str
    origin: str
    path: str
    query_keys: tuple
    approved: bool
    request_fingerprint: str
    outcome: str
    response_fingerprint: str = ""
    error_type: str = ""


class AgentSession:
    """A scoped Session facade suitable for an AI tool implementation."""

    def __init__(self, session, policy=None):
        if not isinstance(session, Session):
            raise TypeError("session must be a mimic.Session")
        self.session = session
        self.policy = policy or AgentPolicy()
        self._audit = []
        self._attempts = 0

    @property
    def audit_log(self):
        """An immutable snapshot of attempted actions, without tokens or bodies."""
        return tuple(self._audit)

    @property
    def remaining_requests(self):
        return self.policy.request_budget - self._attempts

    def request(self, method, path, *, json_body=None, params=None, approved=False, **kw):
        """Authorize and execute one request, recording secret-minimized evidence."""
        method = str(method).upper()
        if method not in self.policy.allowed_methods:
            raise AgentPolicyError(f"{method} is not granted by this agent policy")
        if method in MUTATING_METHODS and self.policy.require_mutation_approval and not approved:
            raise ApprovalRequired(f"{method} requires explicit per-call approval")
        if self._attempts >= self.policy.request_budget:
            raise RequestBudgetExceeded("agent request budget exhausted")

        url = self.session.resolve_url(path)
        parts = urlsplit(url)
        if not any(_path_in_prefix(parts.path or "/", prefix) for prefix in self.policy.path_prefixes):
            raise AgentPolicyError(
                f"path {parts.path or '/'} is outside the granted path prefixes"
            )

        self._attempts += 1
        sequence = self._attempts
        request_fingerprint = _fingerprint(
            {"method": method, "url": url, "json": json_body, "params": params}
        )
        common = {
            "sequence": sequence,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "method": method,
            "origin": _display_origin(parts),
            "path": parts.path or "/",
            "query_keys": tuple(sorted({key for key, _ in parse_qsl(parts.query)})),
            "approved": bool(approved),
            "request_fingerprint": request_fingerprint,
        }
        try:
            result = self.session.request(
                method, url, json=json_body, params=params, refresh=False, **kw
            )
        except Exception as error:
            self._audit.append(
                AgentAction(**common, outcome="error", error_type=type(error).__name__)
            )
            raise
        self._audit.append(
            AgentAction(
                **common,
                outcome="ok",
                response_fingerprint=_fingerprint(result),
            )
        )
        return result

    def tool_catalog(self, endpoints):
        """Build deterministic, secret-free tool descriptors from observed endpoints."""
        tools = []
        used_names = set()
        for endpoint in sorted(
            endpoints, key=lambda item: (item.get("path", ""), item.get("method", ""))
        ):
            method = str(endpoint.get("method", "GET")).upper()
            path = str(endpoint.get("path", "/"))
            if method not in self.policy.allowed_methods:
                continue
            if not any(_path_in_prefix(path, prefix) for prefix in self.policy.path_prefixes):
                continue
            name = _tool_name(method, path)
            if name in used_names:
                name += "_" + hashlib.sha256(f"{method} {path}".encode()).hexdigest()[:8]
            used_names.add(name)
            parameters = {
                key: {"type": "string", "description": f"Value for {{{key}}} in the path"}
                for key in re.findall(r"\{([A-Za-z_][A-Za-z0-9_]*)\}", path)
            }
            required = sorted(parameters)
            parameters["query"] = {
                "type": "object",
                "description": "Optional query parameters",
                "additionalProperties": {
                    "anyOf": [
                        {"type": "string"},
                        {"type": "number"},
                        {"type": "boolean"},
                        {"type": "array"},
                    ]
                },
            }
            schemas = endpoint.get("schemas") or {}
            if method in MUTATING_METHODS or schemas.get("request"):
                parameters["json_body"] = schemas.get("request") or {
                    "type": ["object", "array", "string", "number", "boolean", "null"]
                }
            tools.append(
                {
                    "name": name,
                    "description": f"Observed {method} {path}",
                    "input_schema": {
                        "type": "object",
                        "properties": parameters,
                        "required": required,
                        "additionalProperties": False,
                    },
                    "action": {
                        "method": method,
                        "path_template": path,
                        "read_only": method in READ_ONLY_METHODS,
                        "approval_required": method in MUTATING_METHODS
                        and self.policy.require_mutation_approval,
                    },
                    "observed": {
                        "sample_count": endpoint.get("sample_count", 1),
                        "statuses": endpoint.get("statuses")
                        or [endpoint.get("status")],
                        "schemas": schemas,
                    },
                }
            )
        return tools


def _normalize_prefix(prefix):
    prefix = str(prefix or "")
    if not prefix.startswith("/"):
        raise ValueError(f"path prefix must start with '/': {prefix!r}")
    return prefix.rstrip("/") or "/"


def _path_in_prefix(path, prefix):
    if prefix == "/":
        return path.startswith("/")
    return path == prefix or path.startswith(prefix + "/")


def _display_origin(parts):
    host = parts.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    default = 443 if parts.scheme == "https" else 80
    return f"{parts.scheme}://{host}" + (
        f":{parts.port}" if parts.port and parts.port != default else ""
    )


def _fingerprint(value):
    rendered = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return "sha256:" + hashlib.sha256(rendered.encode("utf-8")).hexdigest()


def _tool_name(method, path):
    stem = re.sub(r"[^a-z0-9]+", "_", path.lower()).strip("_") or "root"
    return f"http_{method.lower()}_{stem}"[:64].rstrip("_")

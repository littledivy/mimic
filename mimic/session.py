"""The runtime every generated client is built on.

A Session holds your captured auth and makes calls that look like they came
from the real app. Generated clients subclass App and call self.get/.post.

    from hinge_client import Hinge
    acc = Hinge()          # auto-pulls your captured auth from mitmweb
    acc.get_recs()

Four things a naive replay gets wrong are handled here rather than left to the
caller:

- **Cookies live in a jar.** Auth arrives as a single ``Cookie`` header, but a
  server that rotates its session cookie sends the new one in ``Set-Cookie``,
  and an HTTP layer that already carries a ``Cookie`` header will refuse to
  regenerate it. The captured header is therefore parsed into a live jar and
  removed from the headers, so rotation propagates.
- **Every request is bounded.** A connect/read timeout and a retry budget with
  backoff, so one dead socket can't hang a run forever.
- **Per-request headers are never replayed.** Signatures, CSRF tokens and
  nonces are dropped at capture time (`mimic.extract`), and a 403 on such an
  endpoint says so instead of blaming your session.
- **Responses are checked against the shape they were captured with.** A field
  that disappeared becomes a `SchemaDriftError` naming it, rather than a
  `KeyError` three frames away.

All of that is policy, and it lives here rather than in a transport. A
transport performs one round trip; swapping it changes the fingerprint and
nothing else.
"""
import random
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from http.cookies import SimpleCookie
from urllib.parse import urlparse

import requests

from . import extract
from .errors import (
    AuthError,
    RateLimitError,
    RequestError,
    SchemaDriftError,
    SignatureError,
)
from .graphql import parse as parse_graphql
from .identity import Profile
from .shapes import diff as diff_shapes
from .shapes import shape_of
from .sources.mitm import default as default_mitm
from .transport import get_transport


_IDEMPOTENT_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "PUT", "DELETE"})

# Worth retrying: the server is asking us to come back, not rejecting the request.
_RETRY_STATUS = frozenset({429, 500, 502, 503, 504})

# (connect, read) in seconds. The read budget has to cover a slow upload of a
# large photo body, so it is deliberately much larger than the connect budget.
DEFAULT_TIMEOUT = (5, 30)
DEFAULT_ATTEMPTS = 3
DEFAULT_BACKOFF = 0.5
DEFAULT_MAX_SLEEP = 30.0

_JSON_TYPES = ("application/json", "text/json")


class Session:
    """Base URL + reusable headers, with helpers that return parsed JSON.

    Construct one of four ways:
        Session.from_mitm("prod-api.hingeaws.net")   # pull from mitmweb
        Session(base_url=..., headers={...})         # explicit
        Session.from_curl(text)                      # paste a copied cURL
        Session.from_har("session.har")              # load a browser HAR export
        Session.from_profile("hinge", vault)         # a saved, encrypted profile

    Every constructor accepts the same policy knobs:

        timeout=(5, 30)      connect/read seconds; a float or None to disable
        attempts=3            total tries, including the first
        backoff=0.5           base seconds for the exponential backoff
        max_sleep=30          ceiling on any single wait, Retry-After included
        transport="requests"  which HTTP layer to use
        shapes={...}          captured response shapes, for drift detection
    """

    def __init__(self, base_url, headers=None, host=None, mitm=None,
                 transport=None, timeout=DEFAULT_TIMEOUT,
                 attempts=DEFAULT_ATTEMPTS, backoff=DEFAULT_BACKOFF,
                 max_sleep=DEFAULT_MAX_SLEEP, sleeper=None, volatile=None,
                 shapes=None):
        self.base_url = base_url.rstrip("/")
        self.headers = {}
        self.host = host
        self._mitm = mitm  # kept for token refresh
        self._timeout = timeout
        self._attempts = max(1, int(attempts))
        self._backoff = backoff
        self._max_sleep = max_sleep
        self._sleep = sleeper or time.sleep
        self._transport = get_transport(transport)
        self.set_headers(headers or {})

        # Per-request headers we know about, so a 403 can name the real cause.
        # Pass them explicitly when they were dropped during extraction; infer
        # from the headers otherwise.
        if volatile is None:
            volatile = {
                k: v for k, v in self.headers.items()
                if extract.classify(k, v) == "volatile"
            }
        self.volatile = dict(volatile)
        # Captured response shapes, keyed (method, path, operation), for drift
        # detection. Empty unless supplied — a Session built just to replay
        # doesn't need a full capture's worth of bodies.
        self.shapes = dict(shapes or {})
        # The saved profile this came from, when built by `from_profile`. Kept
        # so the persona that justified these headers stays inspectable after
        # the vault is closed.
        self.profile = None

    # ---- headers & cookies --------------------------------------------------
    def set_headers(self, headers):
        """Replace the replayed headers, re-seeding any cookies they carry."""
        self.headers = dict(headers)
        self.seed_cookies()

    def seed_cookies(self):
        """Move a captured ``Cookie`` header into the live jar, then drop it.

        Leaving it as a header is what silently breaks session rotation: the
        HTTP layer only regenerates a ``Cookie`` header when there isn't one
        already, so a server-issued cookie gets stored and never sent.

        If the cookies can't be scoped (no hostname on the base URL, or a
        transport with no jar) the header is left in place — losing the session
        silently would be much worse than keeping the old behaviour.
        """
        key = _find_ci(self.headers, "cookie")
        if key is None:
            return
        jar = self._transport.cookies
        host = urlparse(self.base_url).hostname
        if jar is None or not host:
            return
        raw = self.headers.pop(key)
        secure = self.base_url.lower().startswith("https")
        for name, value in _parse_cookie_header(raw):
            # Scoped to the API host and marked secure over TLS, so replaying
            # through an absolute URL to another host can't leak the session.
            self._transport.set_cookie(name, value, domain=host, path="/",
                                       secure=secure)

    # ---- constructors -------------------------------------------------------
    @classmethod
    def from_mitm(cls, host, mitm=None, **kw):
        mitm = mitm or default_mitm()
        flows = mitm.flows()
        headers = extract.session_headers(flows, host)
        if not headers:
            raise RuntimeError(
                f"no authenticated request to {host} captured yet — "
                f"open the app once so mitmweb sees a real call, then retry"
            )
        return cls(
            extract.base_url(flows, host), headers, host=host, mitm=mitm,
            volatile=extract.volatile_headers(flows, host), **kw
        )

    @classmethod
    def from_curl(cls, text, **kw):
        base_url, headers = _parse_curl(text)
        return cls(base_url, headers, **kw)

    @classmethod
    def from_profile(cls, name, vault, **kw):
        """Build a session from a profile saved in the vault.

        `vault` is anything with a ``load(name) -> bytes`` — normally a
        `mimic.vault.Vault`. It is duck-typed on purpose: this module never
        imports the vault, so `import mimic` stays free of `cryptography`, and
        a caller can replay a profile from anywhere, including memory.

        The profile is validated on the way in. A contradiction that was
        somehow written to disk fails here, naming the headers, rather than
        turning into an unexplained 403 on the first call.
        """
        profile = Profile.from_bytes(vault.load(name)).validate()
        session = cls(profile.base_url, headers=profile.as_headers(),
                      host=profile.host or None, **kw)
        session.profile = profile
        return session

    @classmethod
    def from_har(cls, path, host=None, **kw):
        """Build a session from a HAR file exported from browser devtools.

        With no host, picks the most-requested host in the file.
        """
        from .sources import har
        flows = har.load(path)
        if not host:
            ranked = har.hosts(path)
            if not ranked:
                raise RuntimeError("HAR file has no entries")
            host = ranked[0][0]
        headers = extract.session_headers(flows, host)
        if not headers:
            raise RuntimeError(f"no authenticated request to {host} in the HAR file")
        return cls(
            extract.base_url(flows, host), headers, host=host,
            volatile=extract.volatile_headers(flows, host), **kw
        )

    # ---- calls --------------------------------------------------------------
    def request(self, method, path, json=None, params=None, refresh=None,
                retry=None, attempts=None, timeout=None, raw=False, **kw):
        """Make a request and return its parsed body.

        Failed responses raise ``requests.HTTPError`` or a subclass of it. The
        extra types only ever add structure: ``RateLimitError`` carries
        ``retry_after``, ``SchemaDriftError`` carries the field that changed, and
        ``SignatureError`` names the per-request headers that made the endpoint
        unreplayable.

        ``refresh`` controls the auth-refresh retry: by default it applies to
        idempotent methods only, and ``refresh=True`` additionally allows one
        for a non-idempotent method such as POST. ``retry`` controls the
        429/5xx/connection retry budget the same way — ``retry=True`` opts a
        non-idempotent method into retrying, ``retry=False`` opts out entirely.
        """
        method = method.upper()
        url = path if path.startswith("http") else f"{self.base_url}{path}"
        timeout = self._timeout if timeout is None else timeout
        budget = self._attempts if attempts is None else max(1, int(attempts))
        may_retry = (method in _IDEMPOTENT_METHODS) if retry is None else bool(retry)
        may_refresh = refresh is True or (
            refresh is None and method in _IDEMPOTENT_METHODS
        )
        refreshed = False  # one re-pull per call, never a loop

        for attempt in range(1, budget + 1):
            last = attempt == budget
            try:
                r = self._transport.request(
                    method, url, headers=self.headers, params=params, json=json,
                    timeout=timeout, **kw
                )
            except (requests.ConnectionError, requests.Timeout):
                # No response to inspect; connection failures are worth another
                # go exactly when the method is safe to repeat.
                if last or not may_retry:
                    raise
                self._wait(attempt)
                continue

            # A DPoP nonce challenge is not a credential failure. §8/§9 of
            # RFC 9449 have the server answer a proof carrying no nonce with
            # `use_dpop_nonce` and a fresh `DPoP-Nonce`, and the request is
            # worth one more try with the proof re-signed around it. The
            # transport decides whether `r` was such a challenge, and it says
            # no for anything that isn't, so every other 401 below still goes
            # to the refresh branch exactly as it did before.
            #
            # `not last` for the same reason the refresh branch has it: the
            # budget can be 1, and falling out of the loop on a challenge would
            # leave `None` where a response was due.
            if r.status_code in (400, 401) and not last and self._transport.absorb_nonce(r):
                continue

            # Only retry on a credential set mitmweb has actually changed, so a
            # refresh miss can't turn into an unauthenticated retry. `not last`
            # matters: without it the loop can fall out of its final iteration
            # and return None where a response was due.
            if r.status_code == 401 and may_refresh and not refreshed and not last:
                if self._repull():
                    refreshed = True
                    continue

            if r.status_code in _RETRY_STATUS and not last and may_retry:
                self._wait(attempt, retry_after=_retry_after(r))
                continue

            # Check the statuses mimic can explain before delegating to the
            # transport, which would otherwise mask them with a generic
            # HTTPError and lose the field that actually helps.
            if r.status_code == 429:
                raise RateLimitError(
                    f"{method} {path} rate limited after {attempt} "
                    f"attempt{'s' if attempt > 1 else ''}",
                    retry_after=_retry_after(r), response=r,
                )
            if r.status_code == 403 and self.volatile:
                raise SignatureError(
                    f"{method} {path} rejected the request, and it signs its own "
                    f"requests — replaying the capture can't fix this",
                    response=r, headers=self.volatile,
                    field=sorted(self.volatile)[0],
                )
            if r.status_code == 401:
                raise AuthError(
                    f"{method} {path} rejected the captured credentials and they "
                    f"could not be refreshed — re-capture the app's traffic",
                    response=r,
                )
            # Whatever the transport raises for a status it has no better name
            # for lands here as a plain requests.HTTPError, which is not a
            # MimicError and so escapes every `except MimicError` in the CLI and
            # in user code. A 404 or a 503 is still a failed response, and the
            # taxonomy says failed responses are RequestError.
            try:
                self._transport.raise_for_status(r)
            except requests.HTTPError as exc:
                raise RequestError(
                    f"{method} {path} answered {r.status_code}",
                    response=r, request=r.request,
                ) from exc
            return self._parse(r, method, path, json=json, raw=raw)

        # Unreachable while every `continue` above is guarded by `not last`;
        # kept so a future edit can't turn an exhausted budget into a silent
        # None where the caller expects a body.
        raise AssertionError("retry budget exhausted without a response")

    def get(self, path, **kw):
        return self.request("GET", path, **kw)

    def post(self, path, json=None, **kw):
        return self.request("POST", path, json=json, **kw)

    def put(self, path, json=None, **kw):
        return self.request("PUT", path, json=json, **kw)

    def patch(self, path, json=None, **kw):
        return self.request("PATCH", path, json=json, **kw)

    def delete(self, path, json=None, **kw):
        return self.request("DELETE", path, json=json, **kw)

    def head(self, path, **kw):
        return self.request("HEAD", path, **kw)

    def options(self, path, **kw):
        return self.request("OPTIONS", path, **kw)

    def close(self):
        self._transport.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    # ---- internals ----------------------------------------------------------
    def _repull(self):
        """Re-pull captured auth from mitmweb. True only if it actually changed."""
        if not (self.host and self._mitm):
            return False
        # Must bypass the cache: re-reading a cached listing would hand back the
        # same expired token and report "nothing changed".
        new_headers = extract.session_headers(self._mitm.flows(fresh=True), self.host)
        if not new_headers or new_headers == self.headers:
            return False
        self.set_headers(new_headers)
        return True

    def _wait(self, attempt, retry_after=None):
        """Sleep before another attempt: honor Retry-After, else full jitter.

        Full jitter (uniform over the whole window) rather than fixed backoff,
        because a burst of clients retrying in lockstep is what turns a blip
        into an outage.
        """
        if retry_after is not None:
            delay = min(max(retry_after, 0.0), self._max_sleep)
        else:
            ceiling = min(self._backoff * (2 ** (attempt - 1)), self._max_sleep)
            delay = random.uniform(0, ceiling)
        self._sleep(delay)

    def _parse(self, r, method=None, path=None, json=None, raw=False):
        """Parsed body, checked against the captured shape.

        Two ways a live response can diverge from the capture it was generated
        against, both of which otherwise surface far from their cause:

        - it claims JSON but isn't, so a caller expecting a dict gets a string;
        - it is JSON, but a field the generated client reads is gone or has
          changed type, which reads as a missing key or a silently wrong value.
        """
        if raw:
            return r.text
        if not r.content:
            return None
        try:
            body = r.json()
        except ValueError:
            pass
        else:
            self._check_shape(r, body, method, path, json)
            return body

        ctype = (r.headers.get("content-type") or "").split(";")[0].strip().lower()
        if ctype in _JSON_TYPES or ctype.endswith("+json"):
            where = f"{method or ''} {path or ''}".strip() or getattr(r, "url", "")
            raise SchemaDriftError(
                f"{where} answered {r.status_code} with {ctype} that isn't JSON: "
                f"{_preview(r.text)}",
                response=r, field="body", expected=ctype, got=_preview(r.text),
            )
        return r.text

    def _check_shape(self, r, body, method, path, request_json):
        """Raise if the response no longer matches the captured shape."""
        if not self.shapes or not method or not path:
            return
        expected = self.shapes.get(self._shape_key(method, path, request_json))
        if not expected:
            return
        drift = diff_shapes(expected, shape_of(body))
        if drift:
            field, want, got = drift
            where = f"{method} {path.split('?')[0]}"
            raise SchemaDriftError(
                f"{where} no longer matches the response it was generated "
                f"against: {field} was {want}, now {got}",
                response=r, field=field, expected=want, got=got,
            )

    @staticmethod
    def _shape_key(method, path, request_json):
        """Shape lookup key. GraphQL operations share a URL, so the operation
        name is part of the key."""
        gql = parse_graphql(request_json)
        return (method, path.split("?")[0], gql["operation"] if gql else None)


class App(Session):
    """Subclass this in a generated client and add named methods.

    class Hinge(App):
        HOST = "prod-api.hingeaws.net"
        def get_recs(self):
            return self.post("/rec/v2", {"playerId": self.player_id})
    """

    HOST = None

    def __init__(self, base_url=None, headers=None, host=None, mitm=None, **kw):
        if base_url is None:
            if not self.HOST:
                raise TypeError(
                    f"{type(self).__name__}() needs base_url=... (or a HOST class "
                    f"attribute to pull captured auth from)"
                )
            mitm = mitm or default_mitm()
            flows = mitm.flows()
            headers = extract.session_headers(flows, self.HOST)
            if not headers:
                raise RuntimeError(
                    f"no authenticated request to {self.HOST} captured yet — "
                    f"open the app once so mitmweb sees a real call, then retry"
                )
            base_url = extract.base_url(flows, self.HOST)
            host = self.HOST
            kw.setdefault("volatile", extract.volatile_headers(flows, self.HOST))
        super().__init__(base_url, headers=headers, host=host, mitm=mitm, **kw)


def _find_ci(mapping, name):
    """The key in `mapping` equal to `name` case-insensitively, or None."""
    for key in mapping:
        if key.lower() == name:
            return key
    return None


def _parse_cookie_header(raw):
    """`a=1; b="2"` -> [("a", "1"), ("b", "2")].

    SimpleCookie handles the quoting and edge cases properly; the naive split is
    only a fallback so a malformed header can never cost us the whole session.
    """
    parsed = SimpleCookie()
    try:
        parsed.load(raw)
    except Exception:  # pragma: no cover - SimpleCookie is very permissive
        parsed = SimpleCookie()
    pairs = [(m.key, m.value) for m in parsed.values()]
    if pairs:
        return pairs
    out = []
    for chunk in raw.split(";"):
        key, _, value = chunk.partition("=")
        if key.strip():
            out.append((key.strip(), value.strip()))
    return out


def _retry_after(r):
    """`Retry-After` as seconds — either delta-seconds or an HTTP date."""
    raw = (r.headers.get("Retry-After") or "").strip()
    if not raw:
        return None
    try:
        return max(0.0, float(raw))
    except ValueError:
        pass
    try:
        when = parsedate_to_datetime(raw)
    except (TypeError, ValueError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return max(0.0, (when - datetime.now(timezone.utc)).total_seconds())


def _preview(text, limit=60):
    """A short, single-line glimpse of a body, for error messages."""
    squashed = " ".join((text or "").split())
    return squashed[:limit] + ("…" if len(squashed) > limit else "")


def _parse_curl(text):
    """Minimal `curl 'URL' -H 'k: v' ...` parser for the paste fallback."""
    import shlex

    tokens = shlex.split(text.replace("\\\n", " "))
    url, headers = None, {}
    i = 0
    while i < len(tokens):
        t = tokens[i]
        if t in ("-H", "--header"):
            i += 1
            k, _, v = tokens[i].partition(":")
            headers[k.strip()] = v.strip()
        elif t.startswith("http"):
            url = t
        i += 1
    if not url:
        raise ValueError("no URL found in cURL text")
    parts = urlparse(url)
    return f"{parts.scheme}://{parts.netloc}", headers

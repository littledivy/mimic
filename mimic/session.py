"""The runtime every generated client is built on.

A Session holds your captured auth and makes calls that look like they came
from the real app. Generated clients subclass App and call self.get/.post.

    from hinge_client import Hinge
    acc = Hinge()          # auto-pulls your captured auth from mitmweb
    acc.get_recs()
"""
import requests
from urllib.parse import urljoin, urlsplit

from . import extract
from .sources.mitm import Mitm


_IDEMPOTENT_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "PUT", "DELETE"})
DEFAULT_TIMEOUT = 30
DEFAULT_MAX_RESPONSE_BYTES = 2 * 1024 * 1024


class ScopeViolation(ValueError):
    """Raised before a request can escape the session's allowed origins."""


class ResponseTooLarge(RuntimeError):
    """Raised when a response exceeds the configured in-memory limit."""


class Session:
    """Base URL + reusable headers, with helpers that return parsed JSON.

    Construct one of four ways:
        Session.from_mitm("prod-api.hingeaws.net")   # pull from mitmweb
        Session(base_url=..., headers={...})         # explicit
        Session.from_curl(text)                      # paste a copied cURL
        Session.from_har("session.har")              # load a browser HAR export
    """

    def __init__(
        self,
        base_url,
        headers=None,
        host=None,
        mitm=None,
        *,
        allowed_origins=None,
        timeout=DEFAULT_TIMEOUT,
        max_response_bytes=DEFAULT_MAX_RESPONSE_BYTES,
    ):
        self.base_url = base_url.rstrip("/")
        self.headers = headers or {}
        self.host = host
        self._mitm = mitm  # kept for token refresh
        self._http = requests.Session()
        self.timeout = timeout
        self.max_response_bytes = max_response_bytes
        origins = [self.base_url]
        origins.extend(allowed_origins or ())
        self.allowed_origins = frozenset(_origin(value) for value in origins)

    # ---- constructors -------------------------------------------------------
    @classmethod
    def from_mitm(cls, host, mitm=None):
        mitm = mitm or Mitm()
        flows = mitm.flows()
        headers = extract.session_headers(flows, host)
        if not headers:
            raise RuntimeError(
                f"no authenticated request to {host} captured yet — "
                f"open the app once so mitmweb sees a real call, then retry"
            )
        return cls(extract.base_url(flows, host), headers, host=host, mitm=mitm)

    @classmethod
    def from_curl(cls, text):
        base_url, headers = _parse_curl(text)
        return cls(base_url, headers)

    @classmethod
    def from_har(cls, path, host=None):
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
        return cls(extract.base_url(flows, host), headers, host=host)

    # ---- calls --------------------------------------------------------------
    def request(self, method, path, json=None, params=None, refresh=None, **kw):
        """Make a request and return its parsed body.

        Failed responses raise ``requests.HTTPError``. A 401 refreshes captured
        credentials and retries idempotent methods once. Pass ``refresh=True``
        to explicitly allow one retry for a non-idempotent method such as POST.
        """
        method = method.upper()
        url = self.resolve_url(path)
        timeout = kw.pop("timeout", self.timeout)
        if kw.pop("stream", False):
            raise ValueError("Session returns parsed bodies and does not expose streams")
        headers = dict(self.headers)
        headers.update(kw.pop("headers", {}) or {})
        r = self._http.request(
            method,
            url,
            headers=headers,
            json=json,
            params=params,
            timeout=timeout,
            stream=True,
            **kw,
        )
        _read_bounded(r, self.max_response_bytes)
        should_refresh = refresh is True or (
            refresh is None and method in _IDEMPOTENT_METHODS
        )
        if r.status_code == 401 and should_refresh and self.host and self._mitm:
            # Retry only when mitmweb has a non-empty, changed credential set.
            # Keeping the old headers avoids turning a refresh miss into an
            # unauthenticated retry.
            new_headers = extract.session_headers(self._mitm.flows(), self.host)
            if new_headers and new_headers != self.headers:
                self.headers = new_headers
                return self.request(
                    method, path, json=json, params=params, refresh=False, **kw
                )
        r.raise_for_status()
        return _parse(r)

    def resolve_url(self, path):
        """Resolve a request target and reject origins outside this session's scope."""
        if not isinstance(path, str) or not path:
            raise ScopeViolation("request path must be a non-empty string")
        url = urljoin(self.base_url + "/", path)
        target = urlsplit(url)
        if target.username is not None or target.password is not None:
            raise ScopeViolation("request URLs may not contain credentials")
        if target.fragment:
            raise ScopeViolation("request URLs may not contain fragments")
        origin = _origin(url)
        if origin not in self.allowed_origins:
            allowed = ", ".join(sorted(self.allowed_origins))
            raise ScopeViolation(
                f"request origin {origin!r} is outside session scope ({allowed})"
            )
        return url

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


class App(Session):
    """Subclass this in a generated client and add named methods.

    class Hinge(App):
        HOST = "prod-api.hingeaws.net"
        def get_recs(self):
            return self.post("/rec/v2", {"playerId": self.player_id})
    """

    HOST = None

    def __init__(self, **kw):
        if not kw and self.HOST:
            got = Session.from_mitm(self.HOST)
            super().__init__(got.base_url, got.headers, host=got.host, mitm=got._mitm)
        else:
            super().__init__(**kw)


def _parse(r):
    try:
        return r.json()
    except ValueError:
        return r.text


def _origin(url):
    """Canonical HTTP(S) origin used for exact request-scope comparisons."""
    parts = urlsplit(str(url))
    scheme = parts.scheme.lower()
    if scheme not in {"http", "https"} or not parts.hostname:
        raise ScopeViolation(f"invalid HTTP(S) origin: {url!r}")
    try:
        port = parts.port
    except ValueError as error:
        raise ScopeViolation(f"invalid origin port: {url!r}") from error
    default = 443 if scheme == "https" else 80
    host = parts.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    return f"{scheme}://{host}" + (f":{port}" if port and port != default else "")


def _read_bounded(response, limit):
    """Materialize a streamed response without allowing unbounded agent output."""
    if limit is None:
        response._content = b"".join(response.iter_content(chunk_size=64 * 1024))
        response._content_consumed = True
        return
    if limit < 1:
        response.close()
        raise ValueError("max_response_bytes must be positive or None")
    try:
        declared = int(response.headers.get("content-length", ""))
    except (TypeError, ValueError):
        declared = None
    if declared is not None and declared > limit:
        response.close()
        raise ResponseTooLarge(
            f"response Content-Length {declared} exceeds {limit} byte limit"
        )
    body = bytearray()
    for chunk in response.iter_content(chunk_size=64 * 1024):
        body.extend(chunk)
        if len(body) > limit:
            response.close()
            raise ResponseTooLarge(f"response exceeds {limit} byte limit")
    response._content = bytes(body)
    response._content_consumed = True


def _parse_curl(text):
    """Minimal `curl 'URL' -H 'k: v' ...` parser for the paste fallback."""
    import shlex
    from urllib.parse import urlsplit

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
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}", headers

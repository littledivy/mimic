"""Read captured traffic from a running mitmweb instance.

mitmweb exposes a JSON API on http://127.0.0.1:8081. Auth is a token passed
once as a query param, which sets a session cookie; subsequent requests reuse
the cookie. This module pulls the raw flows and normalizes them into the shape
that the runtime Session and the AI codegen step consume.

Bodies are not part of the `/flows` listing — each one costs a separate
`content.data` request. Asking for every endpoint's request and response that
way is two round-trips per endpoint, so `capture()` instead takes the whole
capture, bodies included, in a single `GET /flows/dump`.
"""
import os
import threading
import time
from io import BytesIO

import requests

from ..errors import MimicError

DEFAULT_URL = os.environ.get("MITM_URL", "http://127.0.0.1:8081")

#: The token `mimic record` pins mitmweb to, and the default the client uses.
#:
#: This is not a historical default that stopped working. mitmproxy 11+ sets
#: `web_password` to `secrets.token_hex(16)` when it isn't given one, so a bare
#: `mitmweb` has a different token on every start and "test" is rejected with a
#: 403 on every single API call. mimic launches mitmweb itself, so it pins the
#: token it will then read with (`mimic.cli._mitmweb_cmd`). Set MITM_TOKEN if
#: you run mitmweb by hand with your own password.
DEFAULT_TOKEN = os.environ.get("MITM_TOKEN", "mimic")

#: How long a fetched capture stays usable. Long enough that constructing an app
#: in a loop reuses one fetch, short enough that a capture you just made is
#: visible almost immediately.
CACHE_TTL = 5.0


class MitmError(MimicError):
    pass


class Mitm:
    """A thin client over a running mitmweb's flow API."""

    def __init__(self, url=DEFAULT_URL, token=DEFAULT_TOKEN, cache_ttl=CACHE_TTL):
        self.url = url.rstrip("/")
        self.token = token
        self.cache_ttl = cache_ttl
        self._http = requests.Session()
        self._authed = False
        self._lock = threading.Lock()
        # Cache slots, keyed "flows" (lightweight listing) and "capture"
        # (everything, bodies attached). They are separate reads: one doesn't
        # satisfy the other, because only one of them carries bodies.
        self._cache = {}
        self._at = {}

    # -- auth ----------------------------------------------------------------
    def _auth(self):
        """Exchange the token for a session cookie, once per client.

        Skipped afterwards so repeated reads don't spend a round trip on a
        handshake they've already completed.
        """
        if self._authed:
            return
        try:
            self._http.get(f"{self.url}/", params={"token": self.token}, timeout=5)
        except requests.RequestException as e:
            raise MitmError(
                f"can't reach mitmweb at {self.url} — is it running? "
                f"start it with `mitmweb` (original error: {e})"
            )
        self._authed = True

    # -- reads ---------------------------------------------------------------
    def _cached(self, key):
        with self._lock:
            value = self._at.get(key)
            if value is None or time.monotonic() - value >= self.cache_ttl:
                return None
            return self._cache[key]

    def _store(self, key, value):
        with self._lock:
            self._cache[key] = value
            self._at[key] = time.monotonic()
        return value

    def flows(self, fresh=False):
        """All captured flows as a list of dicts (mitmweb's own schema).

        No bodies — enough to find hosts and pull session headers. Pass
        `fresh=True` to bypass the cache, which is what an auth refresh needs:
        re-reading a cached listing would hand back the same dead token.
        """
        if not fresh and (cached := self._cached("flows")) is not None:
            return cached
        self._auth()
        r = self._http.get(f"{self.url}/flows", timeout=15)
        if r.status_code == 403:
            raise MitmError(
                f"mitmweb at {self.url} rejected our token ({self.token!r}).\n"
                f"    If you started it with `mimic record` that should not "
                f"happen — try restarting it.\n"
                f"    If you run mitmweb yourself, set MITM_TOKEN to its "
                f"`web_password`."
            )
        if r.status_code != 200:
            raise MitmError(f"mitmweb /flows returned {r.status_code}")
        return self._store("flows", r.json())

    def capture(self, fresh=False):
        """Every flow with its request and response bodies, in one request.

        The capture is serialized by mitmproxy itself, so reading it back
        needs mitmproxy importable. That's the `capture` extra, and only this
        method — host listing and session headers work without it.
        """
        if not fresh and (cached := self._cached("capture")) is not None:
            return cached
        self._auth()
        # Dumping a whole session moves every body through one connection.
        r = self._http.get(f"{self.url}/flows/dump", timeout=120)
        if r.status_code != 200:
            raise MitmError(
                f"mitmweb /flows/dump returned {r.status_code} — it needs a "
                f"recent mitmproxy; try `mimic doctor`"
            )
        return self._store("capture", _read_dump(r.content))


def _read_dump(raw):
    """Parse a `/flows/dump` payload into mimic flow dicts, bodies attached."""
    try:
        from mitmproxy import io as mflow
        from mitmproxy import http as mhttp
    except ImportError:
        raise MitmError(
            "reading a full capture needs mitmproxy installed — that is the "
            "`capture` extra:  pipx install mitmproxy   (or `mimic doctor`).\n"
            "Only `mimic hosts` works without it; `learn` and `gen` both need "
            "the request and response bodies."
        )
    flows = []
    with BytesIO(raw) as bio:
        for f in mflow.FlowReader(bio).stream():
            if isinstance(f, mhttp.HTTPFlow):
                flows.append(_to_flow_dict(f))
    return flows


def _to_flow_dict(f):
    req = f.request
    request = {
        "host": req.host,
        "method": req.method,
        "path": req.path,
        "scheme": req.scheme,
        "port": req.port,
        "headers": [list(h) for h in req.headers.items(True)],
        "content": req.raw_content or b"",
    }
    response = {}
    if f.response is not None:
        response = {
            "status_code": f.response.status_code,
            "headers": [list(h) for h in f.response.headers.items(True)],
            "content": f.response.raw_content or b"",
        }
    return {"id": f.id, "request": request, "response": response}


_default = None
_default_lock = threading.Lock()


def default():
    """The shared mitmweb client.

    One instance means one connection, one token handshake, and one cache, so
    building several app objects doesn't re-read the whole capture each time.
    """
    global _default
    with _default_lock:
        if _default is None:
            _default = Mitm()
        return _default

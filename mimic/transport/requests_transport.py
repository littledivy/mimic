"""The default transport: plain `requests`, no extra dependencies.

This is what mimic uses unless you ask for something else. It is chosen for being
legible rather than stealthy — you can point a proxy at it, read the traceback,
and see exactly what went out. `CurlTransport` (fingerprint replay) is the
opposite trade and is opt-in.

It is also where DPoP lives, because DPoP needs the one hook only `requests`
offers: a callback per request on its way to the socket. See `DpopAdapter`.
"""
import requests

from ..dpop import DPOP_HEADER
from .base import Transport

#: How the `Authorization` header names the access token, per RFC 9449 §7.1.
#: `Bearer` is here too because §7.2 requires a client to keep working against a
#: server that hasn't switched yet, and that request still carries a token.
_TOKEN_SCHEMES = ("dpop ", "bearer ")


class DpopAdapter(requests.adapters.HTTPAdapter):
    """Signs every request as it goes out, and reads nonces back.

    Signing here rather than when `request()` is called is not a stylistic
    choice. `requests` re-prepares a request for each redirect and carries
    custom headers across verbatim, so a proof attached once would follow the
    request to a URL it no longer describes — and §4.3 check 9 of RFC 9449
    compares `htu` against the URL that was actually requested, so a server
    rejects it. The adapter is the single point every request passes through,
    once, immediately before the bytes go out.

    The nonce is picked up on the way back, because a server that issues one
    sends it on any response (§8.2) — including a 200, which is the case that
    saves the round trip.
    """

    def __init__(self, signer, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._signer = signer

    def send(self, request, **kwargs):
        request.headers[DPOP_HEADER] = self._signer.proof(
            request.method, request.url,
            access_token=_access_token(request.headers),
        )
        response = super().send(request, **kwargs)
        self._signer.absorb(response)
        return response


def _access_token(headers):
    """The access token a proof has to be bound to, if one is being sent.

    RFC 9449 §4.2 makes `ath` mandatory alongside an access token, and a proof
    without it binds to nothing — the server has no way to tell which token it
    was minted for.
    """
    value = headers.get("Authorization")
    if not value:
        return None
    for scheme in _TOKEN_SCHEMES:
        if value[:len(scheme)].lower() == scheme:
            return value[len(scheme):].strip()
    return None


class RequestsTransport(Transport):
    """One round trip through a persistent `requests.Session`.

    The inner `requests.Session` is what gives us connection pooling and a live
    cookie jar that survives across calls.

    `dpop` is a `mimic.dpop.Signer`. Supplying one turns every request into a
    signed one, and lets a server-issued `DPoP-Nonce` be answered on the next
    try — see `Session.request`, which is where that retry is allowed to
    happen, because retrying is policy and policy isn't a transport's job.
    """

    name = "requests"

    def __init__(self, fingerprint=None, verify=True, dpop=None):
        super().__init__(fingerprint=fingerprint)
        self._http = requests.Session()
        # Exposed rather than wrapped: callers can set proxies, certs, or
        # adapters on it without mimic needing to know about them.
        self.session = self._http
        self.cookies = self._http.cookies
        self.dpop = dpop
        if dpop is not None:
            for prefix in ("http://", "https://"):
                self._http.mount(prefix, DpopAdapter(dpop))
        if not verify:
            self._http.verify = False

    def request(self, method, url, headers=None, params=None, json=None,
                data=None, timeout=None, allow_redirects=True, **kw):
        return self._http.request(
            method,
            url,
            headers=headers,
            params=params,
            json=json,
            data=data,
            timeout=timeout,
            allow_redirects=allow_redirects,
            **kw
        )

    def absorb_nonce(self, r):
        """Take `r`'s `DPoP-Nonce`, if any. True if the caller should re-send.

        False unless DPoP is on, or the nonce is one the last proof didn't
        already carry — see `mimic.dpop.Signer.absorb`, which is where the
        one-retry-per-request limit lives.
        """
        if self.dpop is None:
            return False
        return self.dpop.absorb(r)

    def close(self):
        self._http.close()
"""Fingerprint-preserving transport, on top of `curl_cffi`.

The default transport is plain `requests`, chosen for being legible. This one
exists for the other case: when the server fingerprints the client, a replayed
request has to *handshake* like the app it is impersonating, not just carry the
app's credentials. `curl_cffi` wraps curl-impersonate, so it can be given a
measured JA3/Akamai fingerprint and will send it.

It is deliberately the same contract as `RequestsTransport` — one round trip, a
live cookie jar, the same response attributes, and the same error types.
Everything that makes a Session a Session (retry, auth refresh, cookie seeding,
parsing, error mapping) lives above the seam in `mimic.session` and is
unaffected by which transport is underneath.

That last part takes real work here: `curl_cffi` has its own exception
hierarchy that shares no base class with `requests`, so every error is
translated at this boundary. Without that, `Session`'s retry would quietly stop
catching connection failures and the documented `requests.HTTPError` contract
would not hold.
"""
import requests

from ..errors import DpopError, MimicError
from .base import Transport

#: Named in the error below, and the only way to get this transport.
INSTALL_HINT = "pip install curl_cffi"


def _curl():
    """Import curl_cffi on demand, with an error that says how to get it.

    Deferred so that `mimic.transport` stays importable — and the default
    requests path stays dependency-free — when the extra isn't installed.
    """
    try:
        from curl_cffi import requests as curl_requests
    except ImportError:
        raise ImportError(
            f"the fingerprint transport needs curl_cffi, which isn't installed.\n"
            f"    {INSTALL_HINT}\n"
            f"or keep the default:  transport='requests'  (no extra needed)"
        )
    return curl_requests


class CurlTransport(Transport):
    """One round trip through curl_cffi, wearing a captured fingerprint.

    `fingerprint` is a `mimic.fingerprint.Fingerprint`; anything it measured
    (JA3, Akamai, signature algorithms) is passed through per request.
    `impersonate` is curl_cffi's built-in profile name — the fallback when you
    have a profile to pick but nothing measured.
    """

    name = "curl"

    def __init__(self, fingerprint=None, impersonate=None, dpop=None,
                 **session_kw):
        super().__init__(fingerprint=fingerprint)
        if dpop is not None:
            # Refused rather than half-supported. curl_cffi offers no
            # per-request hook, so the only place to sign is once per call —
            # and a proof signed there follows a redirect to a URL it no longer
            # describes, which §4.3 check 9 of RFC 9449 rejects. Better to say so
            # than to send proofs that work until the first redirect.
            raise DpopError(
                "DPoP proofs are signed on the requests transport only. "
                "curl_cffi gives no hook to sign each request as it goes out, so "
                "a proof could only be attached once per call — and any redirect "
                "would then carry a proof whose `htu` names the wrong URL.\n"
                "Use transport='requests' with dpop=..., or terminate curl "
                "behind a proxy that signs.",
                field="transport", expected="requests", got="curl",
            )
        self._curl_requests = _curl()
        self._exceptions = self._curl_requests.exceptions
        self.impersonate = impersonate
        self._http = self._curl_requests.Session(**session_kw)
        # curl_cffi keeps its own jar, and rotations recorded there are sent on
        # the next call — the same property `Session.seed_cookies` relies on.
        self.cookies = self._http.cookies

    @property
    def supports_fingerprint(self):
        return True

    def request(self, method, url, headers=None, params=None, json=None,
                data=None, timeout=None, allow_redirects=True, **kw):
        options = dict(kw)
        if self.fingerprint is not None:
            options.update(self.fingerprint.curl_kwargs())
        if self.impersonate:
            options["impersonate"] = self.impersonate
        try:
            return self._http.request(
                method,
                url,
                headers=headers,
                params=params,
                json=json,
                data=data,
                timeout=timeout,
                allow_redirects=allow_redirects,
                **options
            )
        except Exception as e:
            raise self._translate(e) from e

    def set_cookie(self, name, value, domain, path="/", secure=False):
        """curl_cffi's jar is name/value keyed, not a `CookieJar`.

        Seeded with *no* domain deliberately. curl keys its jar by
        (name, domain, path), and a `Set-Cookie` from the server arrives with no
        Domain attribute — so a cookie seeded against an explicit host lands in
        a different slot and the rotated value is sent *alongside* the captured
        one. Seeding domain-less lets the server's value replace ours, which is
        what makes rotation work here at all.

        The trade-off: a seeded cookie isn't host-scoped the way the requests
        jar scopes it. Once the server has set its own, normal cookie rules
        apply. Only matters if one Session makes absolute-URL calls to a
        different host.
        """
        self.cookies.set(name, value, path=path, secure=secure)

    def raise_for_status(self, r):
        try:
            r.raise_for_status()
        except Exception as e:
            raise self._translate(e, response=r) from e

    def _translate(self, e, response=None):
        """Map a curl_cffi exception onto the equivalent `requests` one.

        A single translation point is what lets `Session` keep one `except
        requests.Timeout` clause and one `raise_for_status` call without knowing
        which transport it is talking to.
        """
        exc = self._exceptions
        if isinstance(e, (exc.ImpersonateError, NotImplementedError)):
            # Verified against curl_cffi 0.13: reconstructing a ClientHello from
            # a custom JA3 fails for almost any real capture, because curl can
            # only toggle a dozen or so extension IDs and every genuine
            # ClientHello carries others. Say so, and point at the route that
            # does work, instead of surfacing a bare library error.
            return MimicError(
                f"curl could not build a ClientHello from the measured "
                f"fingerprint: {e}\n"
                f"curl-impersonate can only toggle a fixed set of TLS "
                f"extensions, so a JA3 captured from a real app usually names "
                f"ones it refuses. Use a built-in profile instead:\n"
                f"    transport='curl', impersonate='safari_ios'\n"
                f"or drop the fingerprint and use transport='requests'."
            )
        # Timeout before ConnectionError: curl's Timeout may inherit from it.
        if isinstance(e, exc.Timeout):
            return requests.Timeout(str(e), response=response)
        if isinstance(e, exc.ConnectionError):
            return requests.ConnectionError(str(e), response=response)
        if isinstance(e, exc.HTTPError):
            return requests.HTTPError(str(e), response=response)
        return e

    def close(self):
        self._http.close()

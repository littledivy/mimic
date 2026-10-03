"""The HTTP seam every request goes through.

A transport performs exactly one round trip and owns nothing but connection
state and the cookie jar. Everything *policy* — retrying, refreshing a dead
session, parsing and validating the body — lives in `mimic.session`, above this
line. That split is what lets the same Session semantics run over any transport,
and lets the policy be tested without a network.

`RequestsTransport` ships and is the default. `get_transport` already resolves a
"curl" name, for a fingerprint transport that will replay a captured TLS/HTTP2
fingerprint once `curl_cffi` is wired up; it is imported lazily so `curl_cffi`
stays off the default path. Both satisfy the duck-typed response contract
documented on `Transport.request`.
"""
from abc import ABC, abstractmethod


class Transport(ABC):
    """One HTTP client, swappable underneath `mimic.session.Session`.

    A transport is deliberately thin. It does not retry, refresh, or parse: a
    Session drives those, so behaviour stays identical no matter which transport
    is underneath.
    """

    #: Short name used in errors and logs.
    name = "transport"

    def __init__(self, fingerprint=None):
        # Set when this transport can replay a captured client fingerprint. The
        # requests transport ignores it — it has no way to shape a ClientHello —
        # and a Session that holds a fingerprint but gets a transport that can't
        # honour it should say so loudly rather than silently look like a bot.
        self.fingerprint = fingerprint

    #: The live cookie jar, set by each subclass. A class attribute rather than
    #: an instance one, so a subclass can expose it as a read-only property
    #: (curl_cffi builds its jar lazily) without the base __init__ assigning over
    #: it. Mutations persist across calls.
    cookies = None

    #: The `mimic.dpop.Signer` this transport signs with, or None. Only a
    #: transport that can hook every request on its way to the socket can do
    #: this — see `DpopAdapter`.
    dpop = None

    def set_cookie(self, name, value, domain, path="/", secure=False):
        """Add one cookie to the live jar.

        On the seam rather than in `Session` because jars differ: `requests`
        takes a `Cookie` object, curl_cffi takes name/value/domain. Callers
        pass plain values and stay transport-agnostic.
        """
        from requests.cookies import create_cookie

        self.cookies.set_cookie(
            create_cookie(name, value, domain=domain, path=path, secure=secure)
        )

    def raise_for_status(self, r):
        """Raise the canonical error for a bad response.

        A transport whose error hierarchy differs from `requests`' translates
        here. That keeps `Session` transport-agnostic *and* keeps the promise
        that every failed response is a `requests.HTTPError`, whichever
        transport is underneath.
        """
        r.raise_for_status()

    @property
    def supports_fingerprint(self):
        """Whether this transport can actually apply ``self.fingerprint``."""
        return False

    def absorb_nonce(self, r):
        """Take a `DPoP-Nonce` out of the response `r`, if it carries one.

        Returns True when `r` is a nonce challenge the caller should answer by
        sending the request again with a freshly signed proof. False here is the
        right answer for every transport that isn't signing: there's nothing to
        thread a nonce into.

        This is a question, not a decision. The re-send belongs to whoever owns
        the retry budget — `Session` — because that is where "worth another try"
        is decided everywhere else in mimic.
        """
        return False

    @abstractmethod
    def request(self, method, url, headers=None, params=None, json=None,
                data=None, timeout=None, allow_redirects=True, **kw):
        """Perform one request and return the response.

        Returns an object exposing ``status_code`` (int), ``headers`` (case-
        insensitive mapping), ``text`` (str), ``content`` (bytes) and ``json()``.
        ``requests.Response`` satisfies this as-is; the fingerprint transport
        returns its own equivalent.

        Transport errors — a refused connection, a DNS failure, a read timeout
        — propagate as ``requests.RequestException``. Retry decisions belong to
        the caller, which knows whether the method is idempotent.
        """
    def close(self):
        """Release connections. Safe to call more than once."""

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False

"""Pull the reusable part of your captured session out of mitm flows.

The whole trick behind mimic: an app authenticates each request with a bundle of
headers (or cookies) — a bearer token, device ids, a session id. Those are
stable across calls. Capture them once from a real request you made, and you
can craft new calls that the server can't tell apart from your real client.

Not every header in that bundle is reusable. Some are *volatile*: a CSRF token,
a request id, a timestamp, a nonce, a signature. They look identical to the
stable ones on the wire and differ only in that they must be different on every
request. Replaying them is the most common way a captured session stops working,
and the server's rejection gives no hint which header was the problem. So this
module classifies rather than pattern-matches: `session_headers` returns only
what is safe to resend, and `volatile_headers` returns what was deliberately
left behind so a failure can name it.

This module finds the newest authenticated request to a host and keeps only the
headers worth reusing.
"""

# Header names that carry identity/auth/device context worth replaying.
# Anything matching these prefixes or exact names is kept, unless it is volatile.
KEEP_EXACT = {
    "authorization",
    "cookie",
    "user-agent",
    "accept-language",
    "content-type",
    "accept",
}
KEEP_PREFIX = ("x-",)  # x-device-id, x-session-id, x-app-version, x-api-key, …

# Per-request noise that must NOT be replayed — the HTTP layer sets these.
DROP = {
    "content-length",
    "host",
    "connection",
    "accept-encoding",
    "content-encoding",
    "priority",
    "x-forwarded-for",
}

# Headers that are valid exactly once. Sending the captured value back is either
# rejected outright or, worse, silently ignored. The `x-` prefix alone cannot
# tell these apart from x-device-id, which *is* reusable — hence the explicit list.
VOLATILE_EXACT = {
    # Anti-forgery: usually mirrors a cookie of the same name, but replaying the
    # header without refetching the cookie is a guaranteed 403.
    "x-csrf-token",
    "x-xsrf-token",
    "csrf-token",
    "x-csrf",
    # Unique per request by definition.
    "x-request-id",
    "x-correlation-id",
    "x-amzn-trace-id",
    "traceparent",
    "tracestate",
    # Time and nonce bound: replaying is the whole attack these headers prevent.
    "x-timestamp",
    "x-time",
    "x-client-timestamp",
    "x-nonce",
    "x-nonce-count",
    "x-replay-nonce",
    # Request signing. A signature covers the body and a timestamp, so it can
    # never be reused for a different request.
    "x-signature",
    "x-api-signature",
    "x-content-sha256",
    "x-amz-content-sha256",
    "x-goog-signature",
    "x-amz-date",
    # RFC 9449 proofs are bound to one request; the key never leaves the device.
    "dpop",
    "x-dpop",
}

# An Authorization value containing one of these is a *request signature*, not a
# reusable credential — AWS SigV4, Azure SharedKey, OAuth1. The bearer tokens
# worth replaying never look like this.
_SIGNED_AUTH = ("aws4-hmac-", "signature=", "sharedkey", "sharedkeylite")


def classify(name, value=""):
    """Is this header `keep`, `drop`, or `volatile`?

    `drop` is transport noise the HTTP layer sets for us. `volatile` is a header
    that was valid for exactly one request. Everything else is reusable.
    """
    n = name.lower()
    if n in DROP:
        return "drop"
    if n in VOLATILE_EXACT:
        return "volatile"
    if n == "authorization" and any(m in value.lower() for m in _SIGNED_AUTH):
        return "volatile"
    return "keep" if (n in KEEP_EXACT or n.startswith(KEEP_PREFIX)) else "drop"


def _newest_authed(flows, host):
    """The newest request to `host` that carries an Authorization or Cookie.

    "Authed" = has an Authorization or Cookie header. Returns None if none.
    """
    for f in reversed(flows):
        req = f.get("request")
        if not req or req["host"] != host:
            continue
        names = {k.lower() for k, _ in req.get("headers", [])}
        if {"authorization", "cookie"} & names:
            return req
    return None


def session_headers(flows, host):
    """Reusable auth/device headers from your newest authed request to `host`.

    Volatile headers are excluded — see `volatile_headers`. Returns {} if no
    authenticated request was found.
    """
    req = _newest_authed(flows, host)
    if not req:
        return {}
    return {
        k: v for k, v in req["headers"]
        if classify(k, v) == "keep"
    }


def volatile_headers(flows, host):
    """Headers mimic refused to replay from the newest authed request.

    Non-empty only when the app signs its own requests. A failure on such an
    endpoint is not a stale session, and saying so is the difference between a
    five-minute fix and an afternoon.
    """
    req = _newest_authed(flows, host)
    if not req:
        return {}
    return {
        k: v for k, v in req["headers"]
        if classify(k, v) == "volatile"
    }


def base_url(flows, host):
    """Reconstruct the scheme://host base from your newest request to `host`.

    Newest, not first: an app that redirects http to https would otherwise
    leave you replaying against the scheme the app has moved off.
    """
    for f in reversed(flows):
        req = f.get("request")
        if req and req["host"] == host:
            scheme = req.get("scheme", "https")
            port = req.get("port")
            netloc = host
            if port and port not in (80, 443):
                netloc = f"{host}:{port}"
            return f"{scheme}://{netloc}"
    return f"https://{host}"

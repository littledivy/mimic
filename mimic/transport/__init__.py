"""Transports — the swappable HTTP layer under `mimic.session.Session`.

Import from here, not from the submodules:

    from mimic.transport import Transport, RequestsTransport, get_transport
"""
from .base import Transport
from .requests_transport import RequestsTransport


def get_transport(transport="requests", **kw):
    """Resolve a transport: the one place that decides what "requests" means.

    Accepts a name, an already-built `Transport` (returned unchanged, so a
    caller can hand a session a stub), or None for the default. Everything that
    wants an HTTP layer goes through here rather than choosing for itself.

    `CurlTransport` (the optional fingerprint extra) is imported lazily so that
    `curl_cffi` stays a hard-free dependency of the default path.
    """
    if transport is None:
        transport = "requests"
    if not isinstance(transport, str):
        return transport
    if transport == "requests":
        return RequestsTransport(**kw)
    if transport in ("curl", "curl_cffi", "fingerprint"):
        from .curl_transport import CurlTransport  # lazy: optional extra

        return CurlTransport(**kw)
    raise ValueError(
        f"unknown transport {transport!r} — use 'requests' (default) or 'curl'"
    )


__all__ = ["Transport", "RequestsTransport", "get_transport"]
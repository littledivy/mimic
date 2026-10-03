"""The fingerprint transport.

The contract that matters: `Session` owns all the policy, so swapping the
transport underneath must change the fingerprint and nothing else. These tests
run the same scenarios over `requests` and `curl_cffi` and assert the observable
behaviour is identical.

Tests needing the optional extra skip when it isn't installed; the
missing-extra error is tested unconditionally, by simulating its absence.
"""
import importlib.util
import json

import pytest
import requests as vanilla_requests

from mimic import (
    AuthError,
    RateLimitError,
    SchemaDriftError,
    Session,
    SignatureError,
)
from mimic.fingerprint import Fingerprint
from mimic.transport import Transport, get_transport
from mimic.transport.curl_transport import INSTALL_HINT, CurlTransport, _curl

# Only the tests that actually drive curl are skipped when the extra is absent.
# The missing-extra behaviour in particular must be verified in an environment
# where curl_cffi *isn't* installed, which is the situation it describes.
HAS_CURL = importlib.util.find_spec("curl_cffi") is not None
needs_curl = pytest.mark.skipif(not HAS_CURL, reason="needs the fingerprint extra")


# ---- the factory stays honest about opt-in ---------------------------------
def test_the_default_is_still_requests():
    """Installing the extra must not change what anyone gets by default."""
    assert type(get_transport("requests")).__name__ == "RequestsTransport"
    assert type(Session("http://x")._transport).__name__ == "RequestsTransport"


@needs_curl
def test_the_curl_transport_is_reachable_by_name():
    assert get_transport("curl").name == "curl"
    assert get_transport("curl_cffi").name == "curl"


@needs_curl
def test_the_curl_transport_declares_fingerprint_support():
    assert CurlTransport().supports_fingerprint is True
    assert get_transport("requests").supports_fingerprint is False


@needs_curl
def test_it_is_a_transport():
    assert isinstance(CurlTransport(), Transport)


# ---- missing extra ----------------------------------------------------------
def test_the_missing_extra_error_names_the_install_command(monkeypatch):
    """The whole point of a helpful error: the reader can fix it themselves."""
    import builtins
    real_import = builtins.__import__

    def blocked(name, *a, **kw):
        if name.startswith("curl_cffi"):
            raise ImportError("No module named 'curl_cffi'")
        return real_import(name, *a, **kw)

    monkeypatch.setattr(builtins, "__import__", blocked)
    with pytest.raises(ImportError) as exc:
        _curl()

    message = str(exc.value)
    assert INSTALL_HINT in message
    assert "pip install curl_cffi" in message
    # And it points at the way out that needs no extra at all.
    assert "requests" in message


def test_importing_the_module_needs_no_curl_cffi(monkeypatch):
    """`import mimic.transport` must keep working without the extra installed."""
    import importlib
    import builtins
    real_import = builtins.__import__

    def blocked(name, *a, **kw):
        if name.startswith("curl_cffi"):
            raise ImportError("nope")
        return real_import(name, *a, **kw)

    monkeypatch.setattr(builtins, "__import__", blocked)
    module = importlib.import_module("mimic.transport")
    importlib.reload(module)
    assert module.get_transport("requests").name == "requests"


# ---- behaviour parity -------------------------------------------------------
@pytest.fixture(params=["requests", pytest.param("curl", marks=needs_curl)])
def transport_name(request):
    return request.param


def session_over(loopback, transport, **kw):
    return Session(loopback.base_url, {"Authorization": "Bearer t"},
                   transport=get_transport(transport),
                   sleeper=lambda s: None, **kw)


def test_both_transports_parse_json_identically(loopback, transport_name):
    loopback.route("/thing", lambda c: (200, {"Content-Type": "application/json"},
                                        b'{"a":[1,2],"b":{"c":true}}'))
    assert session_over(loopback, transport_name).get("/thing") == \
        {"a": [1, 2], "b": {"c": True}}


def test_both_transports_return_text_for_non_json(loopback, transport_name):
    loopback.route("/thing", lambda c: (200, {"Content-Type": "text/plain"}, b"hi"))
    assert session_over(loopback, transport_name).get("/thing") == "hi"


def test_both_transports_seeded_cookies_reach_the_server(loopback, transport_name):
    loopback.route("/thing", lambda c: (200, {}, b"{}"))
    session = Session(loopback.base_url, {"Cookie": "sid=REAL"},
                      transport=get_transport(transport_name))
    session.get("/thing")
    assert "sid=REAL" in loopback.calls[0].cookie


def test_both_transports_propagate_cookie_rotation(loopback, transport_name):
    """The Layer 0 bug must stay fixed on the new transport too."""
    loopback.route("/thing", lambda c: (
        200, {"Set-Cookie": "sid=ROTATED; Path=/", "Content-Type": "application/json"},
        b'{"n":1}'))
    session = Session(loopback.base_url, {"Cookie": "sid=REAL"},
                      transport=get_transport(transport_name))
    for _ in range(3):
        session.get("/thing")
    assert "ROTATED" in loopback.calls[2].cookie
    assert "REAL" not in loopback.calls[2].cookie


def test_both_transports_raise_the_same_typed_errors(loopback, transport_name):
    loopback.route("/rate", lambda c: (429, {"Retry-After": "1"}, b"{}"))
    loopback.route("/auth", lambda c: (401, {}, b"{}"))
    loopback.route("/signed", lambda c: (403, {}, b"{}"))
    loopback.route("/drift", lambda c: (200, {"Content-Type": "application/json"},
                                        b"<html>no</html>"))
    session = session_over(loopback, transport_name,
                           volatile={"x-signature": "s"})

    for path, expected in (("/rate", RateLimitError), ("/auth", AuthError),
                           ("/signed", SignatureError), ("/drift", SchemaDriftError)):
        with pytest.raises(expected) as exc:
            session.get(path)
        assert isinstance(exc.value, vanilla_requests.HTTPError)


def test_both_transports_retry_the_same_way(loopback, transport_name):
    loopback.route_once("/thing", lambda c: (503, {}, b"busy"),
                        lambda c: (200, {}, b'{"ok":true}'))
    assert session_over(loopback, transport_name).get("/thing") == {"ok": True}
    assert loopback.paths() == ["/thing", "/thing"]


def test_both_transports_do_not_retry_post(loopback, transport_name):
    loopback.route("/thing", lambda c: (500, {}, b"boom"))
    with pytest.raises(vanilla_requests.HTTPError):
        session_over(loopback, transport_name).post("/thing")
    assert len(loopback.calls) == 1


def test_both_transports_report_drift_the_same_way(loopback, transport_name):
    from conftest import make_flow
    from mimic.sources import shapes
    captured = shapes([make_flow(path="/drift2",
                                 resp_body={"data": [{"id": 1, "name": "a"}]})],
                      "api.example.com")
    loopback.route("/drift2", lambda c: (
        200, {"Content-Type": "application/json"}, b'{"data":[{"id":1}]}'))
    session = session_over(loopback, transport_name, shapes=captured)

    with pytest.raises(SchemaDriftError) as exc:
        session.get("/drift2")
    assert exc.value.field == "$.data[].name"


def test_both_transports_honour_timeouts(loopback, transport_name):
    import time
    loopback.route("/slow", lambda c: (time.sleep(3), (200, {}, b"{}"))[1])
    session = Session(loopback.base_url, {}, transport=get_transport(transport_name),
                      timeout=0.3)
    with pytest.raises(Exception):
        session.get("/slow")


def test_both_transports_see_the_same_request(loopback, transport_name):
    """Headers and bodies must reach the server identically either way."""
    loopback.route("/thing", lambda c: (
        200, {"Content-Type": "application/json"},
        json.dumps({"ct": c.headers.get("Content-Type")}).encode()))
    session = session_over(loopback, transport_name)
    assert session.post("/thing", json={"a": 1})["ct"].startswith("application/json")


# ---- the fingerprint actually goes out --------------------------------------
class FakeResponse:
    status_code = 200
    headers = {"Content-Type": "application/json"}
    content = b'{"ok":true}'

    @property
    def text(self):
        return '{"ok":true}'

    def json(self):
        return {"ok": True}

    def raise_for_status(self):
        pass


def spy(**kw):
    """A CurlTransport that records the final curl kwargs instead of sending.

    Wrapping the inner `Session.request` is what sees the fingerprint and
    impersonate options — they are added by the transport, not by the caller.
    curl-impersonate cannot apply most real JA3s (see the limitation test
    below), so the pass-through is verified separately from whether curl itself
    accepts the value.
    """
    transport = CurlTransport(**kw)
    transport.seen = {}

    def record(*a, **options):
        transport.seen.update(options)
        return FakeResponse()

    transport._http.request = record
    return transport


@needs_curl
def test_a_measured_fingerprint_is_passed_to_curl():
    """The JA3 and Akamai strings we measured reach curl verbatim."""
    fp = Fingerprint(ja3="771,4865-4866,0-11-10,29-23-24,0",
                     akamai="1:131072;4:4194304|65535|0|:method,:path")
    recording = spy(fingerprint=fp)
    Session("http://x", {}, transport=recording).get("/thing")
    assert recording.seen["ja3"] == fp.ja3
    assert recording.seen["akamai"] == fp.akamai


@needs_curl
def test_signature_algorithms_travel_with_the_ja3():
    """curl cannot build a ClientHello from a JA3 alone; it needs these too."""
    fp = Fingerprint(ja3="771,4865,0,,", sig_algs=(0x0403, 0x0804, 0x9999))
    recording = spy(fingerprint=fp)
    Session("http://x", {}, transport=recording).get("/thing")
    assert recording.seen["extra_fp"]["tls_signature_algorithms"] == [
        "ecdsa_secp256r1_sha256", "rsa_pss_rsae_sha256"]  # 0x9999 unmapped, dropped


@needs_curl
def test_an_unmeasured_fingerprint_sends_no_ja3():
    """Handing curl a hollow fingerprint would be worse than sending none."""
    recording = spy()
    Session("http://x", {}, transport=recording).get("/thing")
    assert "ja3" not in recording.seen
    assert "akamai" not in recording.seen
    assert "extra_fp" not in recording.seen


@needs_curl
def test_impersonate_is_forwarded(loopback):
    """The route that actually works today: a built-in profile."""
    loopback.route("/thing", lambda c: (200, {}, b"{}"))
    recording = spy(impersonate="safari_ios")
    Session(loopback.base_url, {}, transport=recording).get("/thing")
    assert recording.seen["impersonate"] == "safari_ios"


@needs_curl
def test_impersonate_really_works_against_a_server(loopback):
    """Not just forwarded — a real request wearing a built-in profile."""
    loopback.route("/thing", lambda c: (200, {"Content-Type": "application/json"},
                                        b'{"ok":true}'))
    session = Session(loopback.base_url, {"Authorization": "Bearer t"},
                      transport=CurlTransport(impersonate="safari_ios"))
    assert session.get("/thing") == {"ok": True}


@needs_curl
def test_an_impersonating_transport_returns_the_same_results(loopback):
    """Wearing a profile must not alter what the caller gets back."""
    loopback.route("/thing", lambda c: (200, {"Content-Type": "application/json"},
                                        b'{"ok":true}'))
    plain = session_over(loopback, "curl")
    wearing = Session(loopback.base_url, {"Authorization": "Bearer t"},
                      transport=CurlTransport(impersonate="safari_ios"))
    assert plain.get("/thing") == wearing.get("/thing") == {"ok": True}


# ---- a verified limitation of curl-impersonate, surfaced clearly -----------
@needs_curl
def test_a_real_world_ja3_fails_with_an_actionable_error(loopback):
    """Verified against curl_cffi 0.13: it refuses to reconstruct a ClientHello
    from most captured JA3s, so the error must say what to do instead."""
    from mimic import MimicError

    fp = Fingerprint(
        ja3="771,4865-4866-4867-49195-49196-49199-49200,"
            "0-11-10-65281-35-16-5-13,29-23-24,0",
        sig_algs=(0x0403, 0x0804),
    )
    loopback.route("/thing", lambda c: (200, {}, b"{}"))
    session = Session(loopback.base_url, {}, transport=CurlTransport(fingerprint=fp))
    with pytest.raises(MimicError) as exc:
        session.get("/thing")
    message = str(exc.value)
    assert "impersonate" in message
    assert "transport='requests'" in message

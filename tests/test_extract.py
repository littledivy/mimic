"""Capture-side intelligence: what is safe to replay, and what is not.

`KEEP_PREFIX = ("x-",)` used to keep every x- header, which meant replaying a
captured CSRF token, timestamp, nonce and signature verbatim. These tests pin the
classification that replaced it.
"""
import pytest

from mimic import extract


def flow(host="api.example.com", headers=(), path="/v1/x", scheme="https",
         port=443, method="GET"):
    return {
        "id": "f1",
        "request": {
            "host": host, "method": method, "path": path,
            "scheme": scheme, "port": port,
            "headers": [[k, v] for k, v in headers],
        },
        "response": {"status_code": 200},
    }


AUTHED = [("Authorization", "Bearer tok123"), ("User-Agent", "MyApp/2.1")]


@pytest.mark.parametrize("name", [
    "x-csrf-token", "X-CSRF-Token", "x-xsrf-token",
    "x-timestamp", "x-nonce", "x-nonce-count",
    "x-signature", "x-api-signature", "x-content-sha256",
    "x-amz-date", "x-goog-signature",
    "x-request-id", "x-correlation-id", "traceparent",
    "dpop", "x-dpop",
])
def test_per_request_headers_are_volatile(name):
    """Valid for exactly one request; the `x-` prefix cannot distinguish these."""
    assert extract.classify(name, "whatever") == "volatile"


@pytest.mark.parametrize("name,value", [
    ("Authorization", "Bearer tok"),
    ("Authorization", "Basic dXNlcjpwdw=="),
    ("x-device-id", "abc-123"),
    ("x-app-version", "2.1.0"),
    ("x-api-key", "k-1"),
    ("x-session-id", "s-1"),
    ("User-Agent", "MyApp/2.1"),
    ("Cookie", "sessionid=abc"),
    ("Accept-Language", "en-GB"),
])
def test_reusable_headers_are_kept(name, value):
    assert extract.classify(name, value) == "keep"


@pytest.mark.parametrize("name", [
    "Content-Length", "Host", "Connection", "Accept-Encoding",
    "content-encoding", "x-forwarded-for", "Sec-Fetch-Mode",
])
def test_transport_noise_is_dropped(name):
    assert extract.classify(name, "x") == "drop"


@pytest.mark.parametrize("value", [
    "AWS4-HMAC-SHA256 Credential=AKIA.../20260101/us-east-1/s4/aws4_request, Signature=deadbeef",
    "SharedKey account:deadbeef",
    'OAuth oauth_signature="deadbeef"',
])
def test_signed_authorization_is_volatile_not_a_credential(value):
    """SigV4 et al bake a timestamp into the credential itself.

    The header name is the reusable one, but this value is a per-request
    signature, so the whole thing has to be refused rather than replayed.
    """
    assert extract.classify("Authorization", value) == "volatile"


def test_session_headers_drops_volatile_but_keeps_stable():
    flows = [flow(headers=[
        ("Authorization", "Bearer tok"),
        ("X-Device-Id", "device-9"),
        ("X-Csrf-Token", "stale-csrf"),
        ("X-Request-Id", "old-req"),
        ("Content-Length", "12"),
    ])]
    kept = extract.session_headers(flows, "api.example.com")
    assert kept == {"Authorization": "Bearer tok", "X-Device-Id": "device-9"}


def test_volatile_headers_reports_what_was_refused():
    """So a 403 can name the header instead of blaming the session."""
    flows = [flow(headers=[
        ("Authorization", "Bearer tok"),
        ("X-Csrf-Token", "stale"),
        ("X-Timestamp", "1700000000"),
    ])]
    assert set(extract.volatile_headers(flows, "api.example.com")) == {
        "X-Csrf-Token", "X-Timestamp"
    }


def test_session_headers_uses_the_newest_authenticated_request():
    flows = [
        flow(headers=[("Authorization", "Bearer OLD")]),
        flow(headers=[("Authorization", "Bearer NEW")]),
    ]
    assert extract.session_headers(flows, "api.example.com") == {
        "Authorization": "Bearer NEW"
    }


def test_session_headers_skips_unauthenticated_flows():
    """The newest request may be a telemetry ping with no auth at all."""
    flows = [
        flow(headers=[("Authorization", "Bearer GOOD")]),
        flow(headers=[("User-Agent", "MyApp/2.1")]),
    ]
    assert extract.session_headers(flows, "api.example.com") == {
        "Authorization": "Bearer GOOD"
    }


def test_session_headers_ignores_other_hosts():
    flows = [flow(host="other.example.com", headers=[("Authorization", "Bearer X")])]
    assert extract.session_headers(flows, "api.example.com") == {}
    assert extract.volatile_headers(flows, "api.example.com") == {}


def test_base_url_uses_the_newest_flow():
    """A host that moved http -> https must not be replayed against http."""
    flows = [
        flow(scheme="http", port=80),
        flow(scheme="https", port=443),
    ]
    assert extract.base_url(flows, "api.example.com") == "https://api.example.com"


def test_base_url_keeps_a_nonstandard_port():
    assert extract.base_url(
        [flow(scheme="http", port=8080)], "api.example.com"
    ) == "http://api.example.com:8080"


def test_base_url_falls_back_to_https():
    assert extract.base_url([], "api.example.com") == "https://api.example.com"

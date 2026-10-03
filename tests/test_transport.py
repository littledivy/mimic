"""The transport seam.

`mimic.session` holds all the policy (retry, refresh, parse, error mapping) and
a transport holds one round trip. These tests pin that split, because the
fingerprint transport in a later layer is only additive if it holds: it should be
possible to drop one in without any policy code noticing.
"""
import pytest

from mimic import RateLimitError, Session, Transport
from mimic.transport import RequestsTransport, get_transport
from mimic.session import App


class FakeResponse:
    """Duck-types the response contract in Transport.request's docstring."""

    def __init__(self, status=200, headers=None, body=b"{}", request=None):
        self.status_code = status
        self.headers = headers or {}
        self.content = body
        self.request = request or FakeRequest()

    @property
    def text(self):
        return self.content.decode()

    def json(self):
        import json
        return json.loads(self.content)

    def raise_for_status(self):
        import requests
        if 400 <= self.status_code < 600:
            raise requests.HTTPError(f"{self.status_code} error", response=self)


class FakeRequest:
    method = "GET"
    url = "http://stub/x"


class StubTransport(Transport):
    """Returns scripted responses and records what it was asked for."""

    name = "stub"

    def __init__(self, responses, **kw):
        super().__init__(**kw)
        self._responses = list(responses)
        self.calls = []

    @property
    def cookies(self):
        return self._cookies

    def request(self, method, url, headers=None, params=None, json=None,
                data=None, timeout=None, allow_redirects=True, **kw):
        self.calls.append({
            "method": method, "url": url, "headers": headers,
            "json": json, "timeout": timeout,
        })
        return self._responses.pop(0) if len(self._responses) > 1 else self._responses[0]


def session_with(responses, sleeper=None, **kw):
    transport = StubTransport(responses, **kw.pop("transport_kw", {}))
    return Session("http://stub", {"Authorization": "Bearer t"},
                   transport=transport, sleeper=sleeper, **kw), transport


def test_session_drives_a_foreign_transport_without_changes():
    """The property Layer 2 depends on: policy is transport-agnostic."""
    session, transport = session_with([FakeResponse(body=b'{"ok":true}')])
    assert session.get("/thing") == {"ok": True}
    assert transport.calls[0]["method"] == "GET"
    assert transport.calls[0]["url"] == "http://stub/thing"


def test_retry_policy_works_over_a_foreign_transport():
    session, transport = session_with([
        FakeResponse(503), FakeResponse(200, body=b'{"ok":true}'),
    ], sleeper=lambda s: None)
    assert session.get("/thing") == {"ok": True}
    assert len(transport.calls) == 2


def test_rate_limit_maps_over_a_foreign_transport():
    session, _ = session_with(
        [FakeResponse(429, {"Retry-After": "2"})], sleeper=lambda s: None
    )
    with pytest.raises(RateLimitError) as exc:
        session.get("/thing")
    assert exc.value.retry_after == 2.0


def test_timeout_reaches_the_transport():
    session, transport = session_with([FakeResponse()], timeout=(1, 2))
    session.get("/thing")
    assert transport.calls[0]["timeout"] == (1, 2)


def test_absolute_urls_bypass_the_base_url():
    session, transport = session_with([FakeResponse()])
    session.get("http://elsewhere/abs")
    assert transport.calls[0]["url"] == "http://elsewhere/abs"


# ---- the factory ------------------------------------------------------------
def test_get_transport_default():
    transport = get_transport("requests")
    assert isinstance(transport, RequestsTransport)
    assert transport.name == "requests"
    assert transport.fingerprint is None
    assert transport.cookies is transport.session.cookies
    transport.close()


def test_get_transport_is_the_default_when_unspecified():
    assert isinstance(Session("http://x")._transport, RequestsTransport)


def test_get_transport_rejects_an_unknown_name():
    with pytest.raises(ValueError, match="unknown transport"):
        get_transport("carrier-pigeon")


def test_requests_transport_declines_fingerprint_support():
    """A fingerprint it cannot honour must not silently look honoured."""
    transport = get_transport("requests")
    assert transport.supports_fingerprint is False


# ---- App construction -------------------------------------------------------
class FakeMitm:
    """Stands in for the running mitmweb instance."""

    def __init__(self, flows):
        self._flows = flows
        self.fresh_calls = 0

    def flows(self, fresh=False):
        self.fresh_calls += 1 if fresh else 0
        return self._flows


AUTH_FLOWS = [{
    "id": "f1",
    "request": {
        "host": "api.example.com", "method": "GET", "path": "/v1/x",
        "scheme": "https", "port": 443,
        "headers": [["Authorization", "Bearer tok"], ["X-Csrf-Token", "stale"]],
    },
    "response": {"status_code": 200},
}]


def captured(token):
    """One authenticated flow carrying `token`."""
    return [{
        "id": "f1",
        "request": {
            "host": "api.example.com", "method": "GET", "path": "/v1/x",
            "scheme": "https", "port": 443,
            "headers": [["Authorization", token]],
        },
        "response": {"status_code": 200},
    }]


class Thing(App):
    HOST = "api.example.com"


def test_app_pulls_captured_auth_when_given_only_a_host():
    app = Thing(mitm=FakeMitm(AUTH_FLOWS))
    assert app.base_url == "https://api.example.com"
    assert app.host == "api.example.com"
    assert app.headers["Authorization"] == "Bearer tok"


def test_auth_refresh_bypasses_the_flow_cache():
    """Re-reading a cached listing would hand back the same dead token."""
    from mimic import Session

    class Rotating:
        def __init__(self):
            self.n = 0
            self.fresh_calls = 0

        def flows(self, fresh=False):
            if fresh:
                self.fresh_calls += 1
                self.n += 1
            return captured(f"Bearer {self.n}")

    mitm = Rotating()
    session = Session("http://stub", {"Authorization": "Bearer 0"},
                      host="api.example.com", mitm=mitm)
    assert session._repull() is True
    assert mitm.fresh_calls == 1
    assert session.headers["Authorization"] == "Bearer 1"


def test_app_refuses_to_replay_volatile_headers_it_pulled():
    app = Thing(mitm=FakeMitm(AUTH_FLOWS))
    assert "X-Csrf-Token" not in app.headers
    assert set(app.volatile) == {"X-Csrf-Token"}


def test_app_explicit_base_url_skips_the_pull():
    app = Thing(base_url="http://localhost:1", headers={"Authorization": "Bearer x"})
    assert app.base_url == "http://localhost:1"
    assert app.volatile == {}


def test_app_without_a_host_or_base_url_is_a_clear_error():
    class NoHost(App):
        pass

    with pytest.raises(TypeError, match="needs base_url"):
        NoHost()


def test_app_reports_an_empty_capture_helpfully():
    with pytest.raises(RuntimeError, match="no authenticated request"):
        Thing(mitm=FakeMitm([]))


# ---- from_curl --------------------------------------------------------------
def test_from_curl_still_builds_a_session():
    session = Session.from_curl(
        """curl 'https://api.example.com/v1/x' -H 'Authorization: Bearer t'""",
        sleeper=lambda s: None,
    )
    assert session.base_url == "https://api.example.com"
    assert session.headers["Authorization"] == "Bearer t"


def test_from_curl_without_a_url_is_an_error():
    with pytest.raises(ValueError, match="no URL"):
        Session.from_curl("curl -H 'Authorization: Bearer t'")

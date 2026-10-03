"""Session runtime behaviour, exercised against a real loopback server.

The cookie-rotation test is the regression test for the bug that motivated this
work: mimic shipped auth as a static `Cookie` header, which makes the HTTP layer
refuse to regenerate it, so every `Set-Cookie` the server sent was recorded in
the cookie jar and then silently never sent.
"""
import pytest
import requests

from conftest import RecordingSleeper
from mimic import (
    AuthError,
    RateLimitError,
    SchemaDriftError,
    Session,
    SignatureError,
)
from mimic.session import _retry_after


# ---- cookie rotation --------------------------------------------------------
def test_server_side_cookie_rotation_reaches_the_next_request(loopback):
    """The regression: a rotated session cookie must actually be sent."""
    state = {"n": 0}

    def rotating(call):
        state["n"] += 1
        if state["n"] == 1:
            return 200, {"Set-Cookie": "sessionid=ROTATED; Path=/"}, b'{"n":1}'
        return 200, {}, b'{"n":2}'

    loopback.route("/thing", rotating)
    session = Session(
        loopback.base_url, {"Cookie": "sessionid=REAL; csrftoken=abc"}
    )

    for _ in range(3):
        session.get("/thing")

    sent = [c.cookie for c in loopback.calls]
    # Order within the header is the jar's business; presence is ours.
    assert set(sent[0].split("; ")) == {"sessionid=REAL", "csrftoken=abc"}
    assert "ROTATED" in sent[1], "rotated cookie never reached the server"
    assert "ROTATED" in sent[2]
    assert "csrftoken=abc" in sent[2], "unrelated captured cookie was dropped"
    assert "sessionid=REAL" not in sent[2], "the rotated cookie did not take"


def test_captured_cookie_is_not_kept_as_a_header(loopback):
    """A lingering static Cookie header is what kills the jar, so it must go."""
    loopback.route("/thing", lambda c: (200, {}, b"{}"))
    session = Session(loopback.base_url, {"Cookie": "sessionid=REAL"})
    assert "Cookie" not in session.headers
    assert session._transport.cookies.get("sessionid", domain="127.0.0.1") == "REAL"


def test_seeded_cookies_are_scoped_to_the_api_host(loopback):
    """Seeding an absolute URL to another host must not leak the session."""
    loopback.route("/thing", lambda c: (200, {}, b"{}"))
    session = Session(loopback.base_url, {"Cookie": "sessionid=REAL"})
    jar = session._transport.cookies
    assert jar.get("sessionid", domain="evil.example.com") is None


def test_set_headers_reseeds_cookies(loopback):
    """A re-pull replaces the credential bundle, cookies included."""
    loopback.route("/thing", lambda c: (200, {}, b"{}"))
    session = Session(loopback.base_url, {"Cookie": "sessionid=OLD"})
    session.set_headers({"Cookie": "sessionid=NEW"})
    session.get("/thing")
    assert "sessionid=NEW" in loopback.calls[0].cookie
    assert "OLD" not in loopback.calls[0].cookie


def test_malformed_cookie_header_still_sends_something(loopback):
    loopback.route("/thing", lambda c: (200, {}, b"{}"))
    session = Session(loopback.base_url, {"Cookie": "weird;; = ; sessionid=REAL"})
    session.get("/thing")
    assert "sessionid=REAL" in loopback.calls[0].cookie


def test_unscopable_cookie_header_is_kept_rather_than_dropped():
    """If the cookies can't be scoped we must not silently lose the session."""
    session = Session("not-a-url", {"Cookie": "sessionid=REAL"})
    assert session.headers.get("Cookie") == "sessionid=REAL"


# ---- timeouts ---------------------------------------------------------------
def test_read_timeout_is_bounded(loopback):
    import time

    loopback.route("/slow", lambda c: (time.sleep(3), (200, {}, b"{}"))[1])
    session = Session(loopback.base_url, {"Authorization": "Bearer t"}, timeout=0.25)

    started = time.monotonic()
    with pytest.raises(requests.Timeout):
        session.get("/slow")
    assert time.monotonic() - started < 2.5, "timeout did not fire promptly"


def test_timeout_can_be_overridden_per_call(loopback):
    loopback.route("/thing", lambda c: (200, {}, b"{}"))
    session = Session(loopback.base_url, {}, timeout=(5, 30))
    session.get("/thing", timeout=(1, 1))  # must not raise


# ---- retry / backoff --------------------------------------------------------
def test_rate_limit_is_retried_then_succeeds(loopback, sleeper):
    """429 with Retry-After: the wait must be the server's, not our own."""
    loopback.route_once(
        "/thing", lambda c: (429, {"Retry-After": "7"}, b'{"e":"slow down"}'),
        lambda c: (200, {}, b'{"ok":true}'),
    )
    session = Session(
        loopback.base_url, {"Authorization": "Bearer t"}, sleeper=sleeper
    )

    assert session.get("/thing") == {"ok": True}
    assert loopback.paths() == ["/thing", "/thing"]
    assert sleeper.delays == [7.0]


def test_rate_limit_exhausting_the_budget_raises(loopback, sleeper):
    loopback.route("/thing", lambda c: (429, {"Retry-After": "3"}, b"{}"))
    session = Session(
        loopback.base_url, {"Authorization": "Bearer t"}, sleeper=sleeper
    )

    with pytest.raises(RateLimitError) as exc:
        session.get("/thing")

    assert exc.value.retry_after == 3.0
    assert len(loopback.calls) == 3  # the budget
    assert sleeper.delays == [3.0, 3.0]


def test_retry_after_from_http_date():
    """A date-valued Retry-After resolves to a delta, never a date object."""
    class FakeResponse:
        headers = {"Retry-After": "Wed, 21 Oct 2015 07:28:00 GMT"}

    # Decades in the past, so the delta clamps to 0 rather than going negative.
    assert _retry_after(FakeResponse()) == 0.0


def test_retry_after_absent_is_none():
    class FakeResponse:
        headers = {}

    assert _retry_after(FakeResponse()) is None


@pytest.mark.parametrize("status", [500, 502, 503, 504])
def test_server_errors_are_retried_for_idempotent_methods(loopback, sleeper, status):
    loopback.route_once(
        "/thing", lambda c: (status, {}, b"boom"),
        lambda c: (200, {}, b'{"ok":true}'),
    )
    session = Session(
        loopback.base_url, {"Authorization": "Bearer t"}, sleeper=sleeper
    )
    assert session.get("/thing") == {"ok": True}
    assert len(loopback.calls) == 2


def test_post_is_not_retried_by_default(loopback, sleeper):
    """POST may have already taken effect; repeating it is not mimic's call."""
    loopback.route("/thing", lambda c: (500, {}, b"boom"))
    session = Session(
        loopback.base_url, {"Authorization": "Bearer t"}, sleeper=sleeper
    )

    with pytest.raises(requests.HTTPError):
        session.post("/thing")
    assert len(loopback.calls) == 1
    assert sleeper.delays == []


def test_post_retry_is_opt_in(loopback, sleeper):
    loopback.route_once(
        "/thing", lambda c: (503, {}, b"busy"),
        lambda c: (200, {}, b'{"ok":true}'),
    )
    session = Session(
        loopback.base_url, {"Authorization": "Bearer t"}, sleeper=sleeper
    )
    assert session.post("/thing", retry=True) == {"ok": True}
    assert len(loopback.calls) == 2


def test_retry_false_opts_out_of_retrying(loopback, sleeper):
    loopback.route("/thing", lambda c: (503, {}, b"busy"))
    session = Session(
        loopback.base_url, {"Authorization": "Bearer t"}, sleeper=sleeper
    )
    with pytest.raises(requests.HTTPError):
        session.get("/thing", retry=False)
    assert len(loopback.calls) == 1


def test_backoff_is_jittered_and_bounded(loopback, sleeper):
    """Full jitter, so a herd of clients doesn't retry in lockstep."""
    loopback.route("/thing", lambda c: (503, {}, b"busy"))
    session = Session(
        loopback.base_url, {"Authorization": "Bearer t"},
        sleeper=sleeper, attempts=5, backoff=0.5,
    )

    with pytest.raises(requests.HTTPError):
        session.get("/thing")

    # ceilings are 0.5, 1, 2, 4 for attempts 1..4
    for attempt, delay in enumerate(sleeper.delays, start=1):
        assert 0 <= delay <= 0.5 * 2 ** (attempt - 1)
    assert len(set(sleeper.delays)) > 1, "backoff was not jittered"


def test_retry_after_is_capped_by_max_sleep(loopback, sleeper):
    """A server claiming 'come back in a day' must not park the caller."""
    loopback.route("/thing", lambda c: (429, {"Retry-After": "86400"}, b"{}"))
    session = Session(
        loopback.base_url, {"Authorization": "Bearer t"},
        sleeper=sleeper, max_sleep=5,
    )
    with pytest.raises(RateLimitError):
        session.get("/thing")
    assert sleeper.delays == [5.0, 5.0]  # 3 attempts => 2 waits


# ---- error mapping ----------------------------------------------------------
def test_schema_drift_when_json_content_type_is_not_json(loopback):
    """A 200 that claims JSON but isn't is drift, not a string to debug later."""
    loopback.route(
        "/thing",
        lambda c: (200, {"Content-Type": "application/json"}, b"<html>nope</html>"),
    )
    session = Session(loopback.base_url, {"Authorization": "Bearer t"})

    with pytest.raises(SchemaDriftError) as exc:
        session.get("/thing")
    assert exc.value.field == "body"
    assert exc.value.expected == "application/json"
    assert "nope" in str(exc.value)
    assert exc.value.diff.startswith("body")


def test_schema_drift_accepts_json_suffix_content_types(loopback):
    loopback.route(
        "/thing",
        lambda c: (200, {"Content-Type": "application/problem+json"}, b"not json"),
    )
    session = Session(loopback.base_url, {"Authorization": "Bearer t"})
    with pytest.raises(SchemaDriftError):
        session.get("/thing")


def test_genuine_non_json_response_still_returns_text(loopback):
    """text/plain is not drift — plenty of endpoints legitimately answer it."""
    loopback.route("/thing", lambda c: (200, {"Content-Type": "text/plain"}, b"hi"))
    session = Session(loopback.base_url, {"Authorization": "Bearer t"})
    assert session.get("/thing") == "hi"


def test_raw_opt_out_returns_text(loopback):
    loopback.route("/thing", lambda c: (200, {"Content-Type": "application/json"}, b"nope"))
    session = Session(loopback.base_url, {"Authorization": "Bearer t"})
    assert session.get("/thing", raw=True) == "nope"


def test_empty_body_is_none(loopback):
    loopback.route("/thing", lambda c: (204, {}, b""))
    session = Session(loopback.base_url, {"Authorization": "Bearer t"})
    assert session.get("/thing") is None


def test_signature_error_names_the_per_request_headers(loopback):
    loopback.route("/thing", lambda c: (403, {}, b'{"error":"SignatureDoesNotMatch"}'))
    session = Session(
        loopback.base_url, {"Authorization": "Bearer t"},
        volatile={"x-amz-date": "20260101T000000Z", "x-signature": "abc"},
    )

    with pytest.raises(SignatureError) as exc:
        session.get("/thing")
    assert set(exc.value.headers) == {"x-amz-date", "x-signature"}
    assert exc.value.field == "x-amz-date"
    assert "signs its own requests" in str(exc.value)


def test_unexhausted_refresh_raises_auth_error(loopback):
    loopback.route("/thing", lambda c: (401, {}, b'{"error":"expired"}'))
    session = Session(loopback.base_url, {"Authorization": "Bearer t"})

    with pytest.raises(AuthError) as exc:
        session.get("/thing")
    assert "re-capture" in str(exc.value)


# ---- auth refresh -----------------------------------------------------------
class FakeMitm:
    """A mitmweb stand-in whose capture can be swapped between calls."""

    def __init__(self, flows):
        self.flows_list = flows
        self.fresh_calls = 0

    def flows(self, fresh=False):
        if fresh:
            self.fresh_calls += 1
        return self.flows_list


def captured(token):
    return [{
        "id": "f1",
        "request": {
            "host": "api.example.com", "method": "GET", "path": "/v1/x",
            "scheme": "https", "port": 443,
            "headers": [["Authorization", token]],
        },
        "response": {"status_code": 200},
    }]


def test_401_triggers_one_repull_and_retry(loopback):
    """mitmweb has a newer token, so re-pull it and try once more."""
    mitm = FakeMitm(captured("Bearer OLD"))
    state = {"n": 0}

    def rotate(call):
        state["n"] += 1
        if state["n"] == 1:
            mitm.flows_list = captured("Bearer NEW")
            return 401, {}, b'{"error":"expired"}'
        return 200, {}, b'{"ok":true}'

    loopback.route("/thing", rotate)
    session = Session(loopback.base_url, {"Authorization": "Bearer OLD"},
                      host="api.example.com", mitm=mitm)

    assert session.get("/thing") == {"ok": True}
    assert len(loopback.calls) == 2
    assert session.headers["Authorization"] == "Bearer NEW"


def test_401_does_not_retry_when_the_capture_is_unchanged(loopback):
    """Re-sending the same dead token is just a second failure."""
    loopback.route("/thing", lambda c: (401, {}, b"{}"))
    session = Session(loopback.base_url, {"Authorization": "Bearer OLD"},
                      host="api.example.com", mitm=FakeMitm(captured("Bearer OLD")))

    with pytest.raises(AuthError):
        session.get("/thing")
    assert len(loopback.calls) == 1


def test_refresh_is_not_attempted_twice_in_one_call(loopback):
    """A server that always 401s must not become an infinite refresh loop."""
    loopback.route("/thing", lambda c: (401, {}, b"{}"))
    mitm = FakeMitm(captured("Bearer OLD"))

    class Rotating:
        def flows(self, fresh=False):
            mitm.flows_list = captured(f"Bearer {len(mitm.flows_list)}")
            return mitm.flows_list

    session = Session(loopback.base_url, {"Authorization": "Bearer OLD"},
                      host="api.example.com", mitm=Rotating())
    with pytest.raises(AuthError):
        session.get("/thing")
    assert len(loopback.calls) == 2


def test_a_single_attempt_budget_still_answers_a_401(loopback):
    """Refresh must not consume the last attempt and return None for a body."""
    loopback.route("/thing", lambda c: (401, {}, b"{}"))
    session = Session(loopback.base_url, {"Authorization": "Bearer OLD"},
                      host="api.example.com", mitm=FakeMitm(captured("Bearer NEW")),
                      attempts=1)
    with pytest.raises(AuthError):
        assert session.get("/thing") is not None
    assert len(loopback.calls) == 1


def test_post_refresh_is_opt_in(loopback):
    """The default stays conservative for non-idempotent methods."""
    loopback.route("/thing", lambda c: (401, {}, b"{}"))
    session = Session(loopback.base_url, {"Authorization": "Bearer OLD"},
                      host="api.example.com", mitm=FakeMitm(captured("Bearer NEW")))
    with pytest.raises(AuthError):
        session.post("/thing")
    assert len(loopback.calls) == 1


def test_post_refresh_works_when_asked(loopback):
    loopback.route_once(
        "/thing", lambda c: (401, {}, b"{}"), lambda c: (200, {}, b'{"ok":true}')
    )
    session = Session(loopback.base_url, {"Authorization": "Bearer OLD"},
                      host="api.example.com", mitm=FakeMitm(captured("Bearer NEW")))
    assert session.post("/thing", refresh=True) == {"ok": True}
    assert len(loopback.calls) == 2


def test_repull_reseeds_cookies(loopback):
    """A refreshed session usually rotates its cookies too."""
    loopback.route_once(
        "/thing", lambda c: (401, {}, b"{}"), lambda c: (200, {}, b'{"ok":true}')
    )
    flows = [{
        "id": "f1",
        "request": {
            "host": "api.example.com", "method": "GET", "path": "/v1/x",
            "scheme": "https", "port": 443,
            "headers": [["Authorization", "Bearer NEW"], ["Cookie", "sid=FRESH"]],
        },
        "response": {"status_code": 200},
    }]
    session = Session(
        loopback.base_url,
        {"Authorization": "Bearer OLD", "Cookie": "sid=STALE"},
        host="api.example.com", mitm=FakeMitm(flows),
    )
    session.get("/thing")
    assert "FRESH" in loopback.calls[1].cookie
    assert "STALE" not in loopback.calls[1].cookie


def test_typed_errors_are_still_requests_httperrors(loopback):
    """The README promises requests.HTTPError; that must keep holding."""
    loopback.route("/thing", lambda c: (429, {"Retry-After": "1"}, b"{}"))
    session = Session(loopback.base_url, {"Authorization": "Bearer t"},
                      sleeper=RecordingSleeper())

    with pytest.raises(requests.HTTPError):
        session.get("/thing")


def test_404_stays_a_plain_http_error(loopback):
    """A plain failure gains no new type — it was never a replay problem."""
    session = Session(loopback.base_url, {"Authorization": "Bearer t"})
    with pytest.raises(requests.HTTPError) as exc:
        session.get("/missing")
    assert not isinstance(exc.value, (AuthError, RateLimitError, SchemaDriftError))


# ---- json bodies ------------------------------------------------------------
def test_post_body_round_trips(loopback):
    loopback.route("/thing", lambda c: (200, {}, b'{"echoed":true}'))
    session = Session(loopback.base_url, {"Authorization": "Bearer t"})
    assert session.post("/thing", json={"a": 1}) == {"echoed": True}
    assert loopback.calls[0].json() == {"a": 1}

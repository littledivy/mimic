"""Boundary and state-synchronisation probes for the capture layer.

Each of these is a way the refactor could be quietly wrong: a cache that doesn't
actually save work, a second backend that didn't get the GraphQL fix, or an
empty result that defeats its own memoisation.
"""
import json

from conftest import make_flow as flow
from conftest import wire_flow
from mimic import App, Session
from mimic.sources import har, mitm, shapes


# ---- building an app must not re-read the capture ---------------------------
def test_building_many_apps_reads_the_capture_once(mitmweb, monkeypatch):
    """The point of the shared client: N apps, one read, not N.

    Also the reason a 100-endpoint app doesn't cost a re-scan per instance.
    """
    mitmweb.flows = [wire_flow(token="Bearer t")]
    monkeypatch.setattr(mitm, "_default", mitm.Mitm(url=mitmweb.url, cache_ttl=60))

    class Thing(App):
        HOST = "api.example.com"

    apps = [Thing() for _ in range(5)]

    assert len({id(a) for a in apps}) == 5           # genuinely distinct
    assert all(a.headers["Authorization"] == "Bearer t" for a in apps)
    assert mitmweb.hits.count("/flows") == 1
    # And no bodies were fetched: building a session only needs headers.
    assert mitmweb.count("/flows/dump") == 0
    assert mitmweb.count("content.data") == 0


def test_the_capture_read_is_cached_within_its_ttl(mitmweb, monkeypatch):
    monkeypatch.setattr(mitm, "_read_dump", lambda raw: [flow(resp_body={"a": 1})])
    client = mitm.Mitm(url=mitmweb.url, cache_ttl=60)
    client.capture()
    client.capture()
    assert len([h for h in mitmweb.hits if h == "/flows/dump"]) == 1


def test_an_expired_cache_is_refetched(mitmweb, monkeypatch):
    monkeypatch.setattr(mitm, "_read_dump", lambda raw: [flow(resp_body={"a": 1})])
    client = mitm.Mitm(url=mitmweb.url, cache_ttl=0)
    client.capture()
    client.capture()
    assert len([h for h in mitmweb.hits if h == "/flows/dump"]) == 2


def test_an_empty_capture_is_cached_not_refetched_forever(mitmweb, monkeypatch):
    """An empty result is falsy; a truthiness check would refetch every time."""
    monkeypatch.setattr(mitm, "_read_dump", lambda raw: [])
    client = mitm.Mitm(url=mitmweb.url, cache_ttl=60)
    assert client.capture() == []
    assert client.capture() == []
    assert len([h for h in mitmweb.hits if h == "/flows/dump"]) == 1


def test_a_stale_cache_never_wins_over_a_newer_capture(mitmweb):
    """Auth refresh depends on this: reading the cache would re-report the old
    token and conclude nothing had changed."""
    mitmweb.flows = [wire_flow(token="Bearer OLD")]
    client = mitm.Mitm(url=mitmweb.url, cache_ttl=60)
    session = Session("https://api.example.com", {"Authorization": "Bearer OLD"},
                      host="api.example.com", mitm=client)

    assert client.flows()[0]["request"]["headers"] == [["Authorization", "Bearer OLD"]]
    mitmweb.flows = [wire_flow(token="Bearer NEW")]  # the app refreshed its token

    # The cached read still shows the old capture; a fresh one sees the new.
    assert client.flows()[0]["request"]["headers"] == [["Authorization", "Bearer OLD"]]
    assert session._repull() is True
    assert session.headers["Authorization"] == "Bearer NEW"


def test_a_refresh_that_finds_nothing_new_does_not_retry(mitmweb):
    """Re-sending an unchanged dead token just fails again."""
    mitmweb.flows = [wire_flow(token="Bearer OLD")]
    client = mitm.Mitm(url=mitmweb.url, cache_ttl=0)
    session = Session("https://api.example.com", {"Authorization": "Bearer OLD"},
                      host="api.example.com", mitm=client)
    assert session._repull() is False


# ---- both backends get the GraphQL fix -------------------------------------
def graphql_har(operation, query, resp):
    return {
        "request": {
            "method": "POST",
            "url": "https://api.example.com/graphql",
            "headers": [{"name": "Content-Type", "value": "application/json"}],
            "postData": {
                "mimeType": "application/json",
                "text": json.dumps({"query": query, "operationName": operation}),
            },
        },
        "response": {"status": 200, "content": {"text": json.dumps(resp)}},
    }


def test_graphql_operations_split_on_the_har_backend_too(tmp_path):
    """Unifying the two backends must not have left HAR behind."""
    path = tmp_path / "gql.har"
    path.write_text(json.dumps({"log": {"entries": [
        graphql_har("GetFeed", "query GetFeed($n: Int) { feed(n: $n) { id } }",
                    {"data": {"feed": []}}),
        graphql_har("GetUser", "query GetUser { user { id } }",
                    {"data": {"user": {"id": 1}}}),
    ]}}))

    eps = har.endpoints(str(path), "api.example.com")
    assert len(eps) == 2
    by_op = {e["operation"]: e for e in eps}
    assert set(by_op) == {"GetFeed", "GetUser"}
    assert by_op["GetFeed"]["variables"] == ["n"]


def test_har_shapes_are_available_for_drift(tmp_path):
    path = tmp_path / "gql.har"
    path.write_text(json.dumps({"log": {"entries": [
        graphql_har("GetUser", "query GetUser { user { id } }",
                    {"data": {"user": {"id": 1}}}),
    ]}}))
    assert har.load(str(path))[0]["request"]["content"]
    got = shapes(har.load(str(path)), "api.example.com")
    assert "$.data.user.id" in got[("POST", "/graphql", "GetUser")]


# ---- shape edge cases through the public API -------------------------------
def test_a_top_level_json_array_gets_a_usable_shape():
    from mimic.shapes import diff, shape_of
    got = shape_of([{"id": 1}])
    assert got == {"$": "array", "$[]": "object", "$[].id": "number"}
    assert diff(got, shape_of([{"id": 2}])) is None
    assert diff(got, shape_of([{"other": 2}]))[0] == "$[].id"


def test_a_shape_of_a_bare_scalar_response():
    from mimic.shapes import diff, shape_of
    assert shape_of(42) == {"$": "number"}
    assert diff(shape_of(42), shape_of(42)) is None
    assert diff(shape_of(42), shape_of("42"))[0] == "$"


def test_a_response_that_changes_object_to_array_is_drift():
    from mimic.shapes import diff, shape_of
    assert diff(shape_of({"d": {}}), shape_of({"d": []})) == ("$.d", "object", "array")


def test_a_json_null_body_is_not_mistaken_for_a_missing_body():
    """`null` is a real JSON body. Reading it as "no body" would fingerprint it
    as an empty object and then flag every later null response as drift."""
    got = shapes([flow(path="/v1/x", resp_body="null")], "api.example.com")
    assert got[("GET", "/v1/x", None)] == {"$": "null"}


def test_a_non_json_body_records_no_shape_rather_than_an_empty_object():
    assert shapes([flow(path="/v1/x", resp_body="<html>")],
                  "api.example.com") == {}

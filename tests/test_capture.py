"""Endpoint extraction and capture cost, through the real backends.

Two things this pins down:

- GraphQL operations on one URL stay distinct endpoints, which is the whole
  reason `endpoints` reads request bodies.
- Reading bodies costs one request, not two per endpoint. Verified against a
  stand-in mitmweb that counts every request it receives, because that is the
  claim that regresses silently.
"""
import pytest

from conftest import N_FLOWS, make_flow as flow
from mimic.sources import endpoints, hosts, shapes
from mimic.sources import mitm


def graphql_flow(operation, query, variables=None, fid="g"):
    return flow(method="POST", path="/graphql", fid=fid,
                req_body={"query": query, "operationName": operation,
                          "variables": variables or {}},
                resp_body={"data": {operation: {"ok": True}}})


# ---- GraphQL endpoint separation -------------------------------------------
def test_two_operations_on_one_path_stay_two_endpoints():
    """The defect this fixes: keying on (method, path) collapsed these into 1."""
    flows = [
        graphql_flow("GetFeed", "query GetFeed($first: Int) { feed(first: $first) { id } }"),
        graphql_flow("SendMessage",
                     "mutation SendMessage($to: ID!, $body: String!) "
                     "{ send(to: $to, body: $body) { id } }"),
    ]
    eps = endpoints(flows, "api.example.com")

    assert len(eps) == 2
    by_op = {e["operation"]: e for e in eps}
    assert set(by_op) == {"GetFeed", "SendMessage"}
    assert by_op["SendMessage"]["operation_type"] == "mutation"


def test_each_graphql_endpoint_carries_its_variables():
    flows = [
        graphql_flow("GetFeed", "query GetFeed($first: Int) { feed(first: $first) { id } }"),
        graphql_flow("SendMessage",
                     "mutation SendMessage($to: ID!, $body: String!) "
                     "{ send(to: $to, body: $body) { id } }"),
    ]
    by_op = {e["operation"]: e for e in endpoints(flows, "api.example.com")}
    assert by_op["GetFeed"]["variables"] == ["first"]
    assert by_op["SendMessage"]["variables"] == ["body", "to"]


def test_the_same_operation_called_twice_is_one_endpoint():
    """Repeated calls with different variables are the same endpoint."""
    flows = [
        graphql_flow("GetFeed", "query GetFeed($first: Int) { feed(first: $first) { id } }",
                     {"first": 10}),
        graphql_flow("GetFeed", "query GetFeed($first: Int) { feed(first: $first) { id } }",
                     {"first": 20}),
    ]
    eps = endpoints(flows, "api.example.com")
    assert len(eps) == 1
    assert '"first": 20' in eps[0]["request_body"]  # latest call wins


def test_graphql_and_rest_paths_do_not_collide():
    flows = [
        graphql_flow("GetFeed", "query GetFeed { feed { id } }"),
        flow(method="POST", path="/v1/x", req_body={"a": 1}, resp_body={"ok": True}),
    ]
    assert len(endpoints(flows, "api.example.com")) == 2


def test_a_rest_body_with_a_query_key_is_not_split_into_operations():
    flows = [
        flow(method="POST", path="/search", req_body={"query": "blue suede shoes"}),
        flow(method="POST", path="/search", req_body={"query": "red boots"}),
    ]
    eps = endpoints(flows, "api.example.com")
    assert len(eps) == 1 and eps[0]["path"] == "/search"


def test_shapes_are_keyed_per_graphql_operation():
    flows = [
        graphql_flow("GetFeed", "query GetFeed { feed { id } }"),
        graphql_flow("GetUser", "query GetUser { user { id name } }"),
    ]
    got = shapes(flows, "api.example.com")
    assert set(got) == {
        ("POST", "/graphql", "GetFeed"), ("POST", "/graphql", "GetUser")
    }
    # Each operation's own response, not one shape shared across the URL.
    assert "$.data.GetFeed.ok" in got[("POST", "/graphql", "GetFeed")]
    assert "$.data.GetUser.ok" in got[("POST", "/graphql", "GetUser")]


# ---- non-GraphQL extraction behaviour ---------------------------------------
def test_latest_capture_of_an_endpoint_wins():
    flows = [
        flow(path="/v1/x", resp_body={"n": 1}, fid="a"),
        flow(path="/v1/x", resp_body={"n": 2}, fid="b"),
    ]
    eps = endpoints(flows, "api.example.com")
    assert len(eps) == 1 and '"n": 2' in eps[0]["response_body"]


def test_query_string_is_stripped_from_the_key_but_kept_for_display():
    eps = endpoints([flow(path="/v1/x?page=2")], "api.example.com")
    assert eps[0]["path"] == "/v1/x"
    assert eps[0]["query"] == "page=2"


def test_other_hosts_are_ignored():
    assert endpoints([flow(host="other.example.com")], "api.example.com") == []


def test_flows_without_bodies_still_yield_structure():
    """A lightweight listing has no content; extraction must not fall over."""
    bare = {"id": "f", "request": {"host": "api.example.com", "method": "GET",
                                   "path": "/v1/x"}, "response": {"status_code": 200}}
    eps = endpoints([bare], "api.example.com")
    assert eps == [{
        "method": "GET", "path": "/v1/x", "literal_paths": ["/v1/x"],
        "path_params": [], "status": 200, "query": "",
        "request_body": "", "response_body": "", "response_shape": {},
    }]


def test_a_flow_with_no_response_yields_no_shape():
    f = flow(resp_body=None)
    eps = endpoints([f], "api.example.com")
    assert eps[0]["status"] == 200 and eps[0]["response_shape"] == {}


def test_binary_body_is_summarised_not_crashed_on():
    eps = endpoints([flow(resp_body=b"\xff\xfe\x00binary")], "api.example.com")
    assert "bytes binary" in eps[0]["response_body"]


def test_empty_capture_yields_nothing():
    assert endpoints([], "api.example.com") == []
    assert hosts([]) == []


def test_shapes_skips_endpoints_with_no_captured_body():
    got = shapes([flow(resp_body=None), flow(path="/v2/y", resp_body={"a": 1})],
                 "api.example.com")
    assert list(got) == [("GET", "/v2/y", None)]


def test_hosts_counts_requests():
    flows = [flow(host="a.com"), flow(host="a.com"), flow(host="b.com")]
    assert hosts(flows) == [("a.com", 2), ("b.com", 1)]


# ---- capture cost -----------------------------------------------------------
def test_capture_takes_one_bulk_request_not_two_per_endpoint(mitmweb):
    """100 flows must not become 200 content.data round-trips."""
    client = mitm.Mitm(url=mitmweb.url, cache_ttl=0)
    # A dump payload we can't parse would raise; assert on the request count
    # before that matters by stubbing the reader.
    mitm._read_dump = lambda raw: [flow(fid=f"f{i}") for i in range(N_FLOWS)]
    try:
        captured = client.capture(fresh=True)
    finally:
        import importlib
        importlib.reload(mitm)

    assert len(captured) == N_FLOWS
    assert mitmweb.count("content.data") == 0, "still fetching bodies one at a time"
    assert mitmweb.hits.count("/flows/dump") == 1


def test_endpoint_extraction_over_a_capture_issues_no_per_flow_requests(mitmweb):
    # Distinct non-numeric paths, so these stay N endpoints and the assertion
    # is about request count rather than about path templating.
    client = mitm.Mitm(url=mitmweb.url, cache_ttl=0)
    mitm._read_dump = lambda raw: [
        flow(path=f"/v1/item{i}", resp_body={"n": i}, fid=f"f{i}")
        for i in range(N_FLOWS)
    ]
    try:
        eps = endpoints(client.capture(fresh=True), "api.example.com")
    finally:
        import importlib
        importlib.reload(mitm)

    assert len(eps) == N_FLOWS
    assert mitmweb.count("content.data") == 0


def test_numeric_paths_collapse_into_one_templated_endpoint(mitmweb):
    """`/v1/0` .. `/v1/99` really are one endpoint, and pretending otherwise is
    what made generated clients unreadable."""
    client = mitm.Mitm(url=mitmweb.url, cache_ttl=0)
    mitm._read_dump = lambda raw: [
        flow(path=f"/v1/{i}", resp_body={"n": i}, fid=f"f{i}") for i in range(N_FLOWS)
    ]
    try:
        eps = endpoints(client.capture(fresh=True), "api.example.com")
    finally:
        import importlib
        importlib.reload(mitm)

    assert len(eps) == 1
    # Named after the response field carrying the value, not the position.
    assert eps[0]["path"] == "/v1/{n}"
    assert eps[0]["path_params"] == ["n"]
    assert len(eps[0]["literal_paths"]) == N_FLOWS


def test_the_token_handshake_happens_once_per_client(mitmweb):
    client = mitm.Mitm(url=mitmweb.url, cache_ttl=60)
    client.flows()
    client.flows()
    # The handshake carries ?token=, and the cached second read does neither.
    assert [h for h in mitmweb.hits if h.startswith("/?")] == [
        f"/?token={mitm.DEFAULT_TOKEN}"]
    assert mitmweb.hits.count("/flows") == 1


def test_a_fresh_read_re_authenticates_only_if_needed(mitmweb):
    """`fresh=True` must bypass the cache without repeating the handshake."""
    client = mitm.Mitm(url=mitmweb.url, cache_ttl=60)
    client.flows()
    client.flows(fresh=True)
    assert mitmweb.hits.count("/flows") == 2
    assert len([h for h in mitmweb.hits if h.startswith("/?")]) == 1


def test_a_cached_capture_is_reused_then_refetched(mitmweb):
    client = mitm.Mitm(url=mitmweb.url, cache_ttl=60)
    mitm._read_dump = lambda raw: [flow()]
    try:
        client.capture()
        client.capture()
        assert len([h for h in mitmweb.hits if h == "/flows/dump"]) == 1
        client.capture(fresh=True)
        assert len([h for h in mitmweb.hits if h == "/flows/dump"]) == 2
    finally:
        import importlib
        importlib.reload(mitm)


def test_flows_and_capture_cache_independently(mitmweb):
    """A cheap listing and a full capture are different reads; neither should
    satisfy the other."""
    client = mitm.Mitm(url=mitmweb.url, cache_ttl=60)
    client.flows()
    assert not [h for h in mitmweb.hits if h == "/flows/dump"]
    mitm._read_dump = lambda raw: [flow()]
    try:
        client.capture()
        assert len([h for h in mitmweb.hits if h == "/flows/dump"]) == 1
    finally:
        import importlib
        importlib.reload(mitm)


def test_an_unreadable_dump_payload_explains_the_extra_dependency(mitmweb, monkeypatch):
    """No mitmproxy installed must say so, not raise ImportError."""
    import builtins
    real_import = builtins.__import__

    def blocked(name, *a, **kw):
        if name.startswith("mitmproxy"):
            raise ImportError("no mitmproxy")
        return real_import(name, *a, **kw)

    monkeypatch.setattr(builtins, "__import__", blocked)
    client = mitm.Mitm(url=mitmweb.url, cache_ttl=0)
    with pytest.raises(mitm.MitmError, match="pipx install mitmproxy"):
        client.capture(fresh=True)


def test_a_failed_dump_status_is_reported(mitmweb):
    client = mitm.Mitm(url=mitmweb.url, cache_ttl=0)
    client._http.get = lambda *a, **kw: type(
        "R", (), {"status_code": 404, "content": b""})()
    with pytest.raises(mitm.MitmError, match="flows/dump"):
        client.capture(fresh=True)


def test_default_client_is_shared():
    assert mitm.default() is mitm.default()

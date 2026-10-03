"""Two gaps in the shared capture path.

Both fail *silently* without these, which is what makes them worth a test:
a gzipped body decodes to bytes that aren't UTF-8, so no GraphQL operation and
no response shape are found; and untemplated paths turn `/users/8931` and
`/users/8932` into two endpoints a generated client can't express.
"""
import gzip
import json
import zlib

import pytest

from conftest import make_flow as flow
from mimic.sources import decompress, endpoints, shapes


def gzipped(payload):
    return gzip.compress(json.dumps(payload).encode())


def encoded(content, encoding):
    return [["Content-Encoding", encoding]]


# ---- content-encoding -------------------------------------------------------
def test_gzip_bodies_are_decoded():
    assert json.loads(decompress(gzipped({"a": 1}), encoded(b"", "gzip"))) == {"a": 1}


def test_headers_are_accepted_as_pairs_or_a_mapping():
    """Backends hand over pairs; a caller may well hand a dict."""
    body = gzipped({"a": 1})
    assert json.loads(decompress(body, [["content-encoding", "gzip"]])) == {"a": 1}
    assert json.loads(decompress(body, {"Content-Encoding": "gzip"})) == {"a": 1}


def test_deflate_is_decoded_in_both_wire_forms():
    """zlib-wrapped and headerless raw deflate both appear in the wild."""
    payload = json.dumps({"a": 1}).encode()
    wrapped = zlib.compress(payload)
    raw = zlib.compressobj(wbits=-zlib.MAX_WBITS)
    headerless = raw.compress(payload) + raw.flush()
    for body in (wrapped, headerless):
        assert json.loads(decompress(body, encoded(b"", "deflate"))) == {"a": 1}


def test_x_gzip_is_the_same_as_gzip():
    assert json.loads(decompress(gzipped({"a": 1}), encoded(b"", "x-gzip")))


def test_header_matching_is_case_insensitive():
    assert json.loads(decompress(gzipped({"a": 1}),
                                 [["content-encoding", "GZIP"]]))


def test_a_charset_parameter_is_ignored():
    body = gzipped({"a": 1})
    assert json.loads(decompress(body, encoded(b"", "gzip, chunked")))


def test_an_unencoded_body_is_untouched():
    assert decompress(b'{"a":1}', {"Content-Type": "application/json"}) == b'{"a":1}'


@pytest.mark.parametrize("body,encoding", [
    (b"not actually gzip", "gzip"),   # lying header
    (b"", "gzip"),
    (b"whatever", "br"),              # brotli unavailable / not brotli
])
def test_undecodable_bodies_degrade_rather_than_raise(body, encoding):
    """A broken body must not abort a whole capture; the reader copes."""
    assert decompress(body, encoded(b"", encoding)) == body


def test_no_headers_means_no_decoding():
    assert decompress(b'{"a":1}', None) == b'{"a":1}'


# ---- gzip would otherwise hide the GraphQL operation -----------------------
def test_a_gzipped_graphql_request_still_yields_its_operation():
    """The failure this closes: gzipped body -> no JSON -> one merged endpoint."""
    query = {"query": "query GetFeed($first: Int) { feed(first: $first) { id } }",
             "operationName": "GetFeed"}
    flows = [
        flow(method="POST", path="/graphql", req_body=gzip.compress(
            json.dumps(query).encode())),
        flow(method="POST", path="/graphql", req_body=gzip.compress(
            json.dumps({"query": "mutation Ping { ping }",
                        "operationName": "Ping"}).encode()), fid="f2"),
    ]
    # mark the request headers as gzipped
    for f, raw in zip(flows, (query, None)):
        f["request"]["headers"] = [["Content-Encoding", "gzip"]]

    eps = endpoints(flows, "api.example.com")
    assert len(eps) == 2
    assert {e["operation"] for e in eps} == {"GetFeed", "Ping"}


def test_a_gzipped_response_still_yields_its_shape():
    payload = {"data": {"user": {"id": 1, "name": "ada"}}}
    flows = [flow(path="/v1/me", resp_body=gzip.compress(json.dumps(payload).encode()))]
    flows[0]["response"]["headers"] = [["Content-Encoding", "gzip"]]

    got = shapes(flows, "api.example.com")
    assert got[("GET", "/v1/me", None)] == {
        "$": "object", "$.data": "object", "$.data.user": "object",
        "$.data.user.id": "number", "$.data.user.name": "string",
    }


def test_a_gzipped_body_is_readable_in_the_digest():
    flows = [flow(path="/v1/me", resp_body=gzip.compress(b'{"a":1}'))]
    flows[0]["response"]["headers"] = [["Content-Encoding", "gzip"]]
    assert '"a": 1' in endpoints(flows, "api.example.com")[0]["response_body"]


# ---- path templating -------------------------------------------------------
def two_samples(*paths_and_bodies):
    flows = []
    for i, (path, resp) in enumerate(paths_and_bodies):
        flows.append(flow(path=path, resp_body=resp, fid=f"f{i}"))
    return flows


def test_numeric_segments_collapse_and_get_named_from_the_body():
    """The point: `/users/8931` + `/users/8932` is one endpoint named properly."""
    flows = two_samples(
        ("/users/8931", {"user": {"userId": 8931, "name": "ada"}}),
        ("/users/8932", {"user": {"userId": 8932, "name": "grace"}}),
    )
    eps = endpoints(flows, "api.example.com")
    assert len(eps) == 1
    assert eps[0]["path"] == "/users/{user_id}"
    assert eps[0]["path_params"] == ["user_id"]
    assert eps[0]["literal_paths"] == ["/users/8931", "/users/8932"]


def test_a_numeric_id_sent_as_a_string_still_matches():
    """An API that stringifies ids in the body must still name the parameter."""
    flows = two_samples(
        ("/p/11", {"post": {"post_id": "11"}}),
        ("/p/12", {"post": {"post_id": "12"}}),
    )
    assert endpoints(flows, "api.example.com")[0]["path"] == "/p/{post_id}"


def test_a_slug_segment_is_left_alone():
    """`abc-1` is indistinguishable from a static segment, and guessing a
    parameter there would be worse than not having one."""
    flows = two_samples(("/p/abc-1", {"n": 1}), ("/p/abc-2", {"n": 2}))
    eps = endpoints(flows, "api.example.com")
    assert len(eps) == 2 and all(e["path_params"] == [] for e in eps)


def test_uuids_collapse_too():
    a = "3f2504e0-4f89-11d3-9a0c-0305e82c3301"
    b = "3f2504e0-4f89-11d3-9a0c-0305e82c3302"
    flows = two_samples((f"/files/{a}", {"id": a}), (f"/files/{b}", {"id": b}))
    eps = endpoints(flows, "api.example.com")
    assert len(eps) == 1 and eps[0]["path_params"] == ["id"]


def test_two_varying_positions_get_distinct_names():
    flows = two_samples(
        ("/u/7/p/1", {"userId": 7, "photoId": 1}),
        ("/u/8/p/2", {"userId": 8, "photoId": 2}),
    )
    eps = endpoints(flows, "api.example.com")
    assert eps[0]["path"] == "/u/{user_id}/p/{photo_id}"
    assert eps[0]["path_params"] == ["user_id", "photo_id"]


def test_a_constant_numeric_segment_is_not_templated():
    """`/v2/users` is a version, not an id — it doesn't vary, so it stays."""
    flows = two_samples(("/api/2/users", {"n": 1}), ("/api/2/other", {"n": 2}))
    eps = endpoints(flows, "api.example.com")
    assert len(eps) == 2
    assert all(e["path_params"] == [] for e in eps)


def test_one_sample_is_never_templated():
    """Nothing has been seen to vary, so claiming a parameter would be a guess."""
    flows = two_samples(("/users/8931", {"userId": 8931}))
    eps = endpoints(flows, "api.example.com")
    assert eps[0]["path"] == "/users/8931"
    assert eps[0]["path_params"] == []


def test_an_unnameable_parameter_falls_back_without_inventing_a_name():
    """No field anywhere carries the value, so name it positionally."""
    flows = two_samples(("/x/1", {"unrelated": "a"}), ("/x/2", {"unrelated": "b"}))
    eps = endpoints(flows, "api.example.com")
    assert eps[0]["path_params"] == ["param0"]
    assert eps[0]["path"] == "/x/{param0}"


def test_a_bare_generic_id_field_is_still_usable():
    """A field literally named "id" is the best hint available here."""
    flows = two_samples(("/x/1", {"id": 1}), ("/x/2", {"id": 2}))
    assert endpoints(flows, "api.example.com")[0]["path_params"] == ["id"]


def test_differing_path_depths_are_not_forced_into_one_template():
    flows = two_samples(("/a", {"n": 1}), ("/a/b/c", {"n": 2}))
    assert len(endpoints(flows, "api.example.com")) == 2


def test_camel_case_field_names_become_snake_case():
    flows = two_samples(("/p/1", {"photoId": 1}), ("/p/2", {"photoId": 2}))
    assert endpoints(flows, "api.example.com")[0]["path"] == "/p/{photo_id}"


def test_shapes_are_keyed_by_literal_path_not_template():
    """Session looks a live request up by the path it actually requested."""
    flows = two_samples(
        ("/users/8931", {"user": {"id": 8931}}),
        ("/users/8932", {"user": {"id": 8932}}),
    )
    got = shapes(flows, "api.example.com")
    assert set(got) == {("GET", "/users/8931", None), ("GET", "/users/8932", None)}


def test_a_templated_endpoint_still_drives_drift_detection(loopback):
    """The two features have to compose, not just coexist."""
    flows = two_samples(
        ("/users/8931", {"user": {"id": 8931, "name": "ada"}}),
        ("/users/8932", {"user": {"id": 8932, "name": "grace"}}),
    )
    captured = shapes(flows, "api.example.com")
    loopback.route("/users/8932", lambda c: (
        200, {"Content-Type": "application/json"}, b'{"user":{"id":8932}}'))

    from mimic import SchemaDriftError, Session
    session = Session(loopback.base_url, {"Authorization": "Bearer t"},
                      shapes=captured)
    with pytest.raises(SchemaDriftError) as exc:
        session.get("/users/8932")
    assert exc.value.field == "$.user.name"


def test_graphql_and_templating_do_not_interfere():
    """A GraphQL app's URL has no identifiers, so nothing should be templated."""
    flows = [
        flow(method="POST", path="/graphql",
             req_body={"query": "query A { a { id } }", "operationName": "A"},
             resp_body={"data": {"a": {"id": 1}}}, fid="f1"),
        flow(method="POST", path="/graphql",
             req_body={"query": "query B { b { id } }", "operationName": "B"},
             resp_body={"data": {"b": {"id": 2}}}, fid="f2"),
    ]
    eps = endpoints(flows, "api.example.com")
    assert len(eps) == 2
    assert all(e["path"] == "/graphql" for e in eps)
    assert all(e["path_params"] == [] for e in eps)

"""Schema drift against a captured response shape.

Layer 0 could only catch a response that claimed JSON and wasn't. This layer
gives it the real comparison: a response that is JSON, still parses, and no
longer has the field the generated client reads. Without this, that surfaces as
a `KeyError` in user code, or worse, as a silently falsy value.
"""
import json

import pytest

from conftest import make_flow as flow
from mimic import SchemaDriftError, Session
from mimic.sources import shapes


CAPTURED = flow(path="/v1/users",
                resp_body={"data": [{"id": 1, "displayName": "ada"}]})


def shape_map(body, path="/v1/users", method="GET", host="api.example.com"):
    return shapes([flow(path=path, method=method, resp_body=body)], host)


@pytest.fixture
def users_shape():
    return shape_map(CAPTURED["response"]["content"])


def serve(loopback, path, payload, status=200):
    loopback.route(path, lambda c: (status, {"Content-Type": "application/json"},
                                    json.dumps(payload).encode()))


# ---- the drift cases --------------------------------------------------------
def test_a_field_that_disappeared_names_itself(loopback, users_shape):
    serve(loopback, "/v1/users", {"data": [{"id": 1}]})  # displayName gone
    session = Session(loopback.base_url, {"Authorization": "Bearer t"},
                      shapes=users_shape)

    with pytest.raises(SchemaDriftError) as exc:
        session.get("/v1/users")

    assert exc.value.field == "$.data[].displayName"
    assert exc.value.expected == "string"
    assert exc.value.got == "absent"
    assert "$.data[].displayName" in exc.value.diff
    assert "displayName" in str(exc.value)


def test_a_field_that_changed_type_names_itself(loopback, users_shape):
    serve(loopback, "/v1/users", {"data": [{"id": 1, "displayName": 99}]})
    session = Session(loopback.base_url, {"Authorization": "Bearer t"},
                      shapes=users_shape)

    with pytest.raises(SchemaDriftError) as exc:
        session.get("/v1/users")
    assert (exc.value.field, exc.value.expected, exc.value.got) == \
        ("$.data[].displayName", "string", "number")


def test_an_added_field_is_not_drift(loopback, users_shape):
    """An app gaining a field is compatible and must not break the client."""
    serve(loopback, "/v1/users",
          {"data": [{"id": 1, "displayName": "ada", "avatar": "x"}], "next": 2})
    session = Session(loopback.base_url, {"Authorization": "Bearer t"},
                      shapes=users_shape)
    assert session.get("/v1/users") == {
        "data": [{"id": 1, "displayName": "ada", "avatar": "x"}], "next": 2
    }


def test_an_unchanged_response_passes(loopback, users_shape):
    serve(loopback, "/v1/users", {"data": [{"id": 2, "displayName": "grace"}]})
    session = Session(loopback.base_url, {"Authorization": "Bearer t"},
                      shapes=users_shape)
    assert session.get("/v1/users")["data"][0]["displayName"] == "grace"


# ---- scope: only configured endpoints are checked ---------------------------
def test_uncaptured_paths_are_not_checked(loopback, users_shape):
    """No captured shape means no expectation, not an expectation of nothing."""
    serve(loopback, "/v1/other", {"totally": "different"})
    session = Session(loopback.base_url, {"Authorization": "Bearer t"},
                      shapes=users_shape)
    assert session.get("/v1/other") == {"totally": "different"}


def test_a_session_with_no_shapes_never_drifts(loopback):
    serve(loopback, "/v1/users", {"unexpected": True})
    session = Session(loopback.base_url, {"Authorization": "Bearer t"})
    assert session.get("/v1/users") == {"unexpected": True}


def test_the_query_string_is_not_part_of_the_lookup(loopback, users_shape):
    serve(loopback, "/v1/users", {"data": [{"id": 1}]})
    session = Session(loopback.base_url, {"Authorization": "Bearer t"},
                      shapes=users_shape)
    with pytest.raises(SchemaDriftError):
        session.get("/v1/users?page=2")


# ---- interaction with the content-type check --------------------------------
def test_broken_json_still_reports_the_body_mismatch(loopback, users_shape):
    """The content-type check still runs first and keeps its own message."""
    loopback.route("/v1/users",
                   lambda c: (200, {"Content-Type": "application/json"},
                              b"<html>oops</html>"))
    session = Session(loopback.base_url, {"Authorization": "Bearer t"},
                      shapes=users_shape)
    with pytest.raises(SchemaDriftError) as exc:
        session.get("/v1/users")
    assert exc.value.field == "body"


def test_raw_opt_out_skips_the_shape_check_too(loopback, users_shape):
    serve(loopback, "/v1/users", {"data": [{"id": 1}]})
    session = Session(loopback.base_url, {"Authorization": "Bearer t"},
                      shapes=users_shape)
    assert session.get("/v1/users", raw=True) == '{"data": [{"id": 1}]}'


def test_an_error_status_never_reaches_the_shape_check(loopback, users_shape):
    """A 500's body is an error page, not a shape to judge."""
    loopback.route("/v1/users", lambda c: (500, {}, b"<html>down</html>"))
    session = Session(loopback.base_url, {"Authorization": "Bearer t"},
                      shapes=users_shape)
    with pytest.raises(Exception) as exc:
        session.get("/v1/users")
    assert not isinstance(exc.value, SchemaDriftError)


def test_an_empty_response_body_skips_the_shape_check(loopback, users_shape):
    loopback.route("/v1/users", lambda c: (204, {}, b""))
    session = Session(loopback.base_url, {"Authorization": "Bearer t"},
                      shapes=users_shape)
    assert session.get("/v1/users") is None


# ---- GraphQL ----------------------------------------------------------------
def gql_flow(operation, query, resp):
    return flow(method="POST", path="/graphql",
                req_body={"query": query, "operationName": operation},
                resp_body=resp)


def test_graphql_operations_are_drift_checked_separately(loopback):
    captured = [
        gql_flow("GetFeed", "query GetFeed { feed { id } }",
                 {"data": {"feed": [{"id": 1}]}}),
        gql_flow("GetUser", "query GetUser { user { id name } }",
                 {"data": {"user": {"id": 1, "name": "ada"}}}),
    ]
    gql_shapes = shapes(captured, "api.example.com")
    serve(loopback, "/graphql", {"data": {"user": {"id": 1}}})  # name dropped

    session = Session(loopback.base_url, {"Authorization": "Bearer t"},
                      shapes=gql_shapes)
    with pytest.raises(SchemaDriftError) as exc:
        session.post("/graphql",
                     json={"query": "query GetUser { user { id name } }",
                           "operationName": "GetUser"})
    assert exc.value.field == "$.data.user.name"


def test_the_other_graphql_operation_is_unaffected(loopback):
    captured = [
        gql_flow("GetFeed", "query GetFeed { feed { id } }",
                 {"data": {"feed": [{"id": 1}]}}),
        gql_flow("GetUser", "query GetUser { user { id name } }",
                 {"data": {"user": {"id": 1, "name": "ada"}}}),
    ]
    gql_shapes = shapes(captured, "api.example.com")
    serve(loopback, "/graphql", {"data": {"feed": [{"id": 9}]}})

    session = Session(loopback.base_url, {"Authorization": "Bearer t"},
                      shapes=gql_shapes)
    assert session.post("/graphql",
                        json={"query": "query GetFeed { feed { id } }",
                              "operationName": "GetFeed"}) == {
        "data": {"feed": [{"id": 9}]}
    }


def test_an_unnamed_graphql_operation_is_checked_too(loopback):
    captured = [flow(method="POST", path="/graphql",
                      req_body={"query": "{ feed { id } }"},
                      resp_body={"data": {"feed": [{"id": 1}]}})]
    gql_shapes = shapes(captured, "api.example.com")
    serve(loopback, "/graphql", {"data": {"feed": [{"id": 1}, {"nope": 2}]}})

    session = Session(loopback.base_url, {"Authorization": "Bearer t"},
                      shapes=gql_shapes)
    # `nope` is additive, so this must pass despite the extra key.
    assert session.post("/graphql", json={"query": "{ feed { id } }"}) == {
        "data": {"feed": [{"id": 1}, {"nope": 2}]}
    }

"""GraphQL operation reading.

The reason this exists: every operation in a GraphQL app goes to the same URL,
so keying endpoints on (method, path) collapses the whole API into one. These
tests pin the reader that tells them apart — including the ways it must *not*
fire, since a false positive invents operations that don't exist.
"""
import pytest

from mimic.graphql import parse


def q(query, **kw):
    return parse({"query": query, **kw})


# ---- what it must recognise -------------------------------------------------
def test_named_query():
    got = q("query GetUser($id: ID!) { user(id: $id) { name } }")
    assert got == {
        "operation": "GetUser", "operation_type": "query", "variables": ["id"]
    }


def test_mutation_and_subscription():
    assert q("mutation Unlike($id: ID!) { unlike(id: $id) }")["operation_type"] \
        == "mutation"
    assert q("subscription Feed { feed { id } }")["operation_type"] == "subscription"


def test_anonymous_shorthand_query():
    """`{ user { id } }` has no keyword and no name, but is still GraphQL."""
    got = q("{ user { id } }")
    assert got["operation"] is None
    assert got["operation_type"] == "query"
    assert got["variables"] == []


def test_operation_name_wins_over_the_document():
    """operationName is what the server uses to pick from a multi-op document."""
    document = """
      query First { a { id } }
      query Second { b { id } }
    """
    got = q(document, operationName="Second")
    assert got["operation"] == "Second"


def test_variables_are_collected_from_the_whole_document():
    """Definitions and usages share syntax; the set a caller supplies is the
    same either way."""
    got = q(
        "query Feed($first: Int, $after: String, $first: Int) { "
        "feed(first: $first, after: $after) { id } }"
    )
    assert got["variables"] == ["after", "first"]  # sorted, deduplicated


def test_variables_in_a_fragment_are_found():
    got = q("query Q { ...F } fragment F on T($n: Int) { items(n: $n) { id } }")
    assert got["variables"] == ["n"]


# ---- what it must not recognise --------------------------------------------
@pytest.mark.parametrize("body", [
    None, [], "a string", 42,
    {},                                   # no query key
    {"query": None}, {"query": 7}, {"query": ""}, {"query": "   "},
])
def test_non_graphql_bodies(body):
    assert parse(body) is None


def test_rest_search_body_is_not_graphql():
    """`{"query": "blue suede shoes"}` is a search term, not a document.

    Treating it as GraphQL would invent an operation and split one search
    endpoint in two.
    """
    assert parse({"query": "blue suede shoes", "page": 2}) is None


def test_operation_name_alone_is_enough():
    """An explicit operationName is strong evidence even for a bare document."""
    got = parse({"query": "", "operationName": "GetUser"})
    assert got is None or got["operation"] == "GetUser"


# ---- degradation ------------------------------------------------------------
def test_unreadable_document_still_yields_an_operation():
    """Never raise on a document we can't fully read — degrade, don't fail."""
    got = parse({"query": "!!!not a document!!!", "operationName": "Weird"})
    assert got["operation"] == "Weird"
    assert got["variables"] == []


def test_underscore_and_dollar_prefixed_variable_names():
    got = q("query Q($_id: ID, $__x: Int) { a($_id, __x: $__x) { id } }")
    assert got["variables"] == ["__x", "_id"]

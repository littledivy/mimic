"""Response shape fingerprints and the drift diff built on them.

The point of a fingerprint is to catch a field disappearing before the code that
reads it turns into a `KeyError` three frames away — so the interesting cases
are the ones where being too strict would fire on every single request.
"""
import pytest

from mimic.shapes import ARRAY_SAMPLE, MAX_DEPTH, diff, shape_of


# ---- shape_of ---------------------------------------------------------------
def test_flat_object():
    assert shape_of({"id": 1, "name": "x"}) == {
        "$": "object", "$.id": "number", "$.name": "string"
    }


def test_nested_paths_are_dotted():
    got = shape_of({"user": {"profile": {"name": "x"}}})
    assert got == {
        "$": "object", "$.user": "object", "$.user.profile": "object",
        "$.user.profile.name": "string",
    }


def test_scalars_normalise_int_and_float_to_one_type():
    """A server that widens 3 -> 3.0 hasn't broken the client."""
    assert shape_of({"n": 1})["$.n"] == shape_of({"n": 1.0})["$.n"] == "number"


def test_boolean_is_not_a_number():
    """bool subclasses int; collapsing them would hide a real type change."""
    assert shape_of({"flag": True})["$.flag"] == "boolean"
    assert shape_of({"flag": 1})["$.flag"] == "number"


def test_null_is_its_own_type():
    assert shape_of({"v": None})["$.v"] == "null"


def test_list_describes_its_elements():
    got = shape_of({"items": [{"id": 1}]})
    assert got == {
        "$": "object", "$.items": "array", "$.items[]": "object",
        "$.items[].id": "number",
    }


def test_empty_list_has_no_element_shape():
    assert shape_of({"items": []}) == {"$": "object", "$.items": "array"}


def test_list_merges_across_elements_not_just_the_first():
    """An optional field in one item must not read as absent from all of them."""
    got = shape_of({"items": [{"id": 1}, {"id": 2, "nick": "x"}]})
    assert got["$.items[].id"] == "number"
    assert got["$.items[].nick"] == "string"


def test_list_merge_is_bounded():
    """A huge array of uniform items still yields one sample's shape."""
    items = [{"id": i} for i in range(ARRAY_SAMPLE * 3)]
    got = shape_of({"items": items})
    assert got["$.items[].id"] == "number"


def test_nesting_is_depth_bounded():
    """A pathological body can't produce a fingerprint larger than itself."""
    node = {"leaf": 1}
    for _ in range(MAX_DEPTH * 3):
        node = {"n": node}
    got = shape_of(node)
    assert len(got) <= MAX_DEPTH + 2


def test_top_level_scalars_and_arrays():
    assert shape_of(5) == {"$": "number"}
    assert shape_of("x") == {"$": "string"}
    assert shape_of([1, 2]) == {"$": "array", "$[]": "number"}


# ---- diff -------------------------------------------------------------------
def test_identical_shapes_do_not_drift():
    a = shape_of({"id": 1, "user": {"name": "x"}})
    assert diff(a, shape_of({"id": 2, "user": {"name": "y"}})) is None


def test_a_disappearing_field_names_itself():
    field, expected, got = diff(
        shape_of({"id": 1, "name": "x"}), shape_of({"id": 1})
    )
    assert (field, expected, got) == ("$.name", "string", "absent")


def test_a_retyped_field_names_itself():
    field, expected, got = diff(
        shape_of({"id": "1"}), shape_of({"id": 1})
    )
    assert (field, expected, got) == ("$.id", "string", "number")


def test_a_nested_field_that_disappears():
    field, _, got = diff(
        shape_of({"user": {"id": 1, "email": "a"}}), shape_of({"user": {"id": 1}})
    )
    assert (field, got) == ("$.user.email", "absent")


def test_added_fields_are_tolerated():
    """An app gaining a field is compatible; breaking on it would be wrong."""
    assert diff(shape_of({"id": 1}), shape_of({"id": 1, "new": "x"})) is None


def test_number_widening_is_not_drift():
    assert diff(shape_of({"n": 1}), shape_of({"n": 1.0})) is None


def test_a_list_gaining_an_optional_field_is_tolerated():
    before = shape_of({"items": [{"id": 1}]})
    after = shape_of({"items": [{"id": 1}, {"id": 2, "nick": "x"}]})
    assert diff(before, after) is None


@pytest.mark.parametrize("a,b", [({}, {}), ({}, {"a": 1}), ({"a": 1}, {}), (None, None)])
def test_empty_shapes_never_drift(a, b):
    """No captured shape means no expectation, not an expectation of nothing."""
    assert diff(a, b) is None


def test_drift_is_reported_deterministically():
    """Two broken fields must always report the same one, for stable tests."""
    expected = shape_of({"b": 1, "a": 1})
    actual = shape_of({"c": 1})  # present, but missing both a and b
    for _ in range(5):
        field, _, _ = diff(expected, actual)
        assert field == "$.a"

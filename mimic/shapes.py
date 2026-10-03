"""Structural fingerprints of a JSON body, and the diff between two of them.

A generated client is written against the response shape that was captured at
generation time. When the app ships a change, the request still succeeds and the
client quietly returns something wrong — a missing field surfaces as a `KeyError`
three frames away, or worse, as a silently falsy value. Comparing a live
response against the captured shape turns that into an error that names the
field.

A "shape" is a flat map of dotted path to type name:

    {"$": "object", "$.user": "object", "$.user.id": "string",
     "$.items": "array", "$.items[].id": "number"}

Lists are merged across a sample of their elements rather than described from
the first one, so an optional field in one item doesn't read as drift on every
other.
"""

#: How deep to walk before stopping. Bounded because a pathological body would
#: otherwise produce a fingerprint far larger than the payload it describes.
MAX_DEPTH = 12

#: How many list elements to merge. Enough to cover the usual "some items omit
#: a nullable field" without scanning a 10k-element response.
ARRAY_SAMPLE = 20


def _scalar(value):
    # bool before int: bool is a subclass of int, and `True` meaning "1" in a
    # fingerprint would hide a real type change.
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "string"
    return type(value).__name__


def shape_of(value, prefix="$", _depth=0):
    """The structural fingerprint of `value`, as path -> type name."""
    if isinstance(value, dict):
        shape = {prefix: "object"}
        if _depth < MAX_DEPTH:
            for key, item in value.items():
                shape.update(shape_of(item, f"{prefix}.{key}", _depth + 1))
        return shape
    if isinstance(value, list):
        shape = {prefix: "array"}
        if value and _depth < MAX_DEPTH:
            merged = {}
            for item in value[:ARRAY_SAMPLE]:
                for path, kind in shape_of(
                    item, f"{prefix}[]", _depth + 1
                ).items():
                    merged.setdefault(path, kind)
            shape.update(merged)
        return shape
    return {prefix: _scalar(value)}


def diff(expected, actual):
    """The first drift between two shapes, as ``(field, expected, got)``.

    Returns None when they agree. Only fields present in `expected` are
    checked: an app adding a field is a compatible change and should not break
    a client written against the old shape, whereas a field disappearing or
    changing type will break exactly the code that reads it.
    """
    if not expected or not actual:
        return None
    for field in sorted(expected):
        want = expected[field]
        got = actual.get(field)
        if got is None:
            return field, want, "absent"
        if got != want:
            return field, want, got
    return None

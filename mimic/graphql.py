"""Just enough GraphQL to tell one operation from another.

A GraphQL app sends every operation to the same URL, so keying endpoints on
`(method, path)` collapses the entire API into one useless endpoint. The
operation name is what distinguishes them — and it is in the request body, which
mimic already captures.

This is a reader, not a parser: a full GraphQL grammar is far more than this
needs. It extracts the operation kind, its name, and the variables it declares,
which is what endpoint identity and codegen both care about. Anything it can't
read (an anonymous shorthand query, a `query` keyword inside a string literal)
degrades to an unnamed `query` rather than failing.
"""
import re

#: The operation keyword and the optional name that follows it.
_OPERATION_RE = re.compile(
    r"\b(query|mutation|subscription)\b\s*([A-Za-z_][A-Za-z0-9_]*)?", re.I
)

#: A variable reference. Definitions and usages use the same syntax, and a valid
#: document declares every variable it uses, so scanning the whole query yields
#: exactly the set a caller has to supply.
_VARIABLE_RE = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)")


def parse(body):
    """Describe a GraphQL request body, or None if it isn't one.

    Returns ``{"operation": str|None, "operation_type": str,
    "variables": [str]}``. The operation name prefers the explicit
    ``operationName`` field, because that is what the server actually uses to
    pick an operation out of a multi-operation document.

    A `query` key alone isn't enough: plenty of REST endpoints take
    `{"query": "blue suede shoes"}` as a search term, and treating those as
    GraphQL would both invent operations and split one search endpoint in two.
    So a body only counts as GraphQL if it names an operation explicitly, or
    the value actually reads as a document — a selection set, or an operation
    keyword. A valid document always has a selection set.
    """
    if not isinstance(body, dict):
        return None
    query = body.get("query")
    if not isinstance(query, str) or not query.strip():
        return None

    match = _OPERATION_RE.search(query)
    named = body.get("operationName")
    if not named and not match and "{" not in query:
        return None

    keyword = match.group(1).lower() if match else "query"
    inferred_name = match.group(2) if match else None

    return {
        "operation": named or inferred_name or None,
        "operation_type": keyword,
        "variables": sorted(set(_VARIABLE_RE.findall(query))),
    }

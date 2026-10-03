"""Deterministic client inference.

Two contracts. The generated client has to actually *work* — same requests,
same parsed bodies as a client written by hand. And a type it cannot trace to
a recorded value has to say so in the generated code, next to the name, rather
than quietly reading as a confident guess.
"""
import pytest

from conftest import Loopback, make_flow
from mimic import App, PersonaConflict
from mimic.codegen_det import client_source, plan, render
from mimic.identity import Persona
from mimic.sources import endpoints

HOST = "api.example.com"
UA = "MyApp/2.1.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)"
HEADERS = [["Authorization", "Bearer t"], ["User-Agent", UA],
           ["X-Device-Id", "D-1"]]


def captured():
    return [
        make_flow(path="/users/8931", headers=HEADERS,
                  resp_body={"user": {"id": 8931, "name": "Ada",
                                      "nickname": None, "score": 4.5}}),
        make_flow(fid="f2", path="/users/8932", headers=HEADERS,
                  resp_body={"user": {"id": 8932, "name": "Bob",
                                      "nickname": None, "score": 3.0}}),
        make_flow(fid="f3", path="/v1/me", headers=HEADERS,
                  resp_body={"id": 7, "tags": ["a", "b"], "active": True}),
        make_flow(fid="f4", path="/rec/v2", method="POST", req_body={"n": 3},
                  headers=HEADERS, resp_body={"ok": True}),
    ]


def source_for(flows=None, **kw):
    return client_source(HOST, endpoints(flows or captured(), HOST), **kw)


def load(source, class_name="ApiClient"):
    """Execute generated source and hand back the class it defined."""
    namespace = {}
    exec(compile(source, "<generated>", "exec"), namespace)
    return namespace[class_name], namespace


# ---- it makes the same calls and parses the same shapes as a hand-written one
class HandWritten(App):
    """What a person would have written, from the same capture."""

    HOST = HOST

    def get_users(self, id):
        return self.get(f"/users/{id}")

    def get_v1_me(self):
        return self.get("/v1/me")

    def post_rec_v2(self, body=None):
        return self.post("/rec/v2", body)


def test_the_generated_client_replays_like_a_hand_written_one(loopback):
    loopback.route("/users/", lambda c: (200, {}, b'{"user": {"id": 1}}'))
    loopback.route("/users/1", lambda c: (200, {}, b'{"user": {"id": 1}}'))
    loopback.route("/v1/me", Loopback.respond({"id": 7, "tags": ["a"],
                                              "active": True}))
    loopback.route("/rec/v2", Loopback.respond({"ok": True}))

    generated, _ = load(source_for())
    for client in (generated(base_url=loopback.base_url),
                   HandWritten(base_url=loopback.base_url)):
        assert client.get_users(1) == {"user": {"id": 1}}
        assert client.get_v1_me() == {"id": 7, "tags": ["a"], "active": True}
        assert client.post_rec_v2({"n": 3}) == {"ok": True}


def test_the_generated_client_sends_the_same_requests(loopback):
    full = {"user": {"id": 8931, "name": "Ada", "nickname": None, "score": 4.5}}
    loopback.route("/users/8931", Loopback.respond(full))
    loopback.route("/v1/me", Loopback.respond({"id": 7}))
    generated, _ = load(source_for())
    client = generated(base_url=loopback.base_url,
                       headers={"Authorization": "Bearer t"})
    client.get_users(8931)

    assert loopback.paths() == ["/users/8931"]
    # Auth comes from the Session the caller built, not from anything the
    # generated file invented.
    assert loopback.calls[0].headers["Authorization"] == "Bearer t"


def test_the_generated_client_parses_the_same_shapes(loopback):
    """Same bodies in, same dicts out — it is not doing its own parsing."""
    payload = {"user": {"id": 8931, "name": "Ada", "nickname": None, "score": 4.5}}
    loopback.route("/users/8931", lambda c: (200, {}, __import__("json")
                                             .dumps(payload).encode()))
    generated, _ = load(source_for())
    body = generated(base_url=loopback.base_url).get_users(8931)
    assert body == payload
    assert isinstance(body["user"]["score"], float)
    assert body["user"]["nickname"] is None


def test_the_generated_client_inherits_drift_detection(loopback):
    """The shapes Layer 1 recorded travel with the client, so a field the app
    stops sending is reported by name instead of a KeyError later."""
    from mimic import SchemaDriftError

    loopback.route("/v1/me", Loopback.respond({"id": 7, "tags": ["a"],
                                              "active": True}))
    generated, _ = load(source_for())
    client = generated(base_url=loopback.base_url)
    assert client.shapes  # populated without the caller passing anything

    loopback.route("/v1/me", Loopback.respond({"id": 7, "tags": ["a"]}))
    with pytest.raises(SchemaDriftError) as exc:
        client.get_v1_me()
    assert "$.active" in str(exc.value)


def test_the_generated_source_is_valid_python():
    compile(source_for(), "<generated>", "exec")


# ---- a type nobody observed is marked unknown, not invented ------------------
def test_a_field_seen_only_as_null_is_emitted_as_explicitly_unknown():
    source = source_for()
    marked = [l for l in source.splitlines()
              if "$.user.nickname" in l and "UNKNOWN" in l]
    assert len(marked) == 1, "the unknown field must be called out exactly once"
    line = marked[0]
    # The unknown field is `Any`, not a plausible concrete type.
    assert "Any" in line
    for guessed in ("str", "int", "bool", "dict", "list"):
        assert guessed not in line


def test_the_unknown_marker_says_why():
    source = source_for()
    assert "capture only ever saw this field as null" in source


def test_a_known_field_next_to_an_unknown_one_is_still_typed():
    source = source_for()
    assert "$.user.name      str" in source
    assert "$.user.id        Union[int, float]" in source


def test_a_path_parameter_is_typed_from_the_value_that_was_recorded():
    """`id` was observed as a JSON number in the response body, so it is
    annotated as a number and the comment says where that came from."""
    source = source_for()
    assert "def get_users(self, id: Union[int, float]) -> dict:" in source
    assert "# id: observed at $.user.id as number" in source


def test_a_path_parameter_with_no_recorded_type_is_admitted_as_such():
    """No body field ever carried this value, so all the capture supports is
    that it appeared in a URL."""
    flows = [make_flow(path="/raw/1234", headers=HEADERS,
                       resp_body={"ok": True}),
             make_flow(fid="f2", path="/raw/5678", headers=HEADERS,
                       resp_body={"ok": True})]
    source = client_source(HOST, endpoints(flows, HOST))
    assert "seen only as a URL segment" in source
    assert "id: str" in source or "param0: str" in source


def test_a_variable_seen_only_as_null_is_unknown_not_guessed():
    """The hard case: the value exists in the capture, so the parameter looks
    typeable — but every time the field was recorded it was null, so there is
    no evidence for a type at all."""
    body = {"operationName": "GetUser",
            "query": "query GetUser($id: ID!) { user(id: $id) { id name } }"}
    flows = [make_flow(path="/graphql", method="POST", req_body=body,
                       headers=HEADERS,
                       resp_body={"user": {"id": None, "name": "Ada"}})]
    source = client_source(HOST, endpoints(flows, HOST))

    assert "id: Any" in source, "a null-only field must not be typed by name"
    marked = [l for l in source.splitlines() if l.strip().startswith("# id:")]
    assert marked and "UNKNOWN" in marked[0]


def test_a_graphql_variable_with_a_known_type_is_typed():
    body = {"operationName": "GetUser",
            "query": "query GetUser($id: ID!) { user(id: $id) { id name } }"}
    flows = [make_flow(path="/graphql", method="POST", req_body=body,
                       headers=HEADERS,
                       resp_body={"user": {"id": 7, "name": "Ada"}})]
    source = client_source(HOST, endpoints(flows, HOST))
    assert "# id: observed at $.user.id as number" in source


def test_a_typed_parameter_is_marked_observed_in_the_generated_code():
    source = source_for()
    assert "# id: observed at $.user.id as number" in source


def test_a_json_number_is_not_narrowed_to_int():
    """JSON does not say whether 4.5 was a float; `Union[int, float]` states
    exactly what was observed instead of picking one."""
    assert "Union[int, float]" in source_for()
    assert ": int" not in source_for()


# ---- inference is a pure function of the capture ----------------------------
def test_the_same_capture_always_generates_the_same_bytes():
    eps = endpoints(captured(), HOST)
    assert client_source(HOST, eps) == client_source(HOST, eps)


def test_plan_describes_the_capture_without_rendering():
    p = plan(HOST, endpoints(captured(), HOST))
    assert p.class_name == "ApiClient"
    assert [m.method for m in p.methods] == ["GET", "GET", "POST"]
    assert [m.name for m in p.methods] == ["get_users", "get_v1_me",
                                           "post_rec_v2"]
    assert p.methods[0].status == 200
    assert ("GET", "/users/8931", None) in p.shapes


def test_render_and_plan_agree():
    p = plan(HOST, endpoints(captured(), HOST))
    assert render(p) == client_source(HOST, endpoints(captured(), HOST))


def test_method_names_do_not_collide():
    flows = [make_flow(path="/v1/me", headers=HEADERS, resp_body={"a": 1}),
             make_flow(fid="f2", path="/v1/me/", headers=HEADERS,
                       resp_body={"a": 1})]
    names = [m.name for m in plan(HOST, endpoints(flows, HOST)).methods]
    assert len(names) == len(set(names))


# ---- the persona is evidence too ---------------------------------------------
def test_the_persona_is_written_into_the_generated_file():
    persona = Persona.from_headers({"User-Agent": UA, "x-device-id": "D-1"})
    source = client_source(HOST, endpoints(captured(), HOST), persona=persona)
    assert "D-1" in source
    assert "user_agent" in source


def test_a_contradictory_persona_stops_generation():
    """The same gate the vault applies at load, applied before a file is
    written from contradictory evidence."""
    persona = Persona.from_headers({"user-agent": UA, "x-platform": "Android"})
    with pytest.raises(PersonaConflict):
        client_source(HOST, endpoints(captured(), HOST), persona=persona)


def test_a_persona_may_be_given_as_plain_headers():
    source = client_source(HOST, endpoints(captured(), HOST),
                           persona={"User-Agent": UA, "x-device-id": "D-1"})
    assert "D-1" in source


# ---- degenerate captures ----------------------------------------------------
def test_an_empty_capture_still_produces_importable_source():
    source = client_source(HOST, [])
    compile(source, "<generated>", "exec")
    assert "CAPTURED_SHAPES = {}" in source


def test_an_endpoint_with_no_body_gets_no_body_parameter():
    source = client_source(HOST, endpoints(
        [make_flow(path="/ping", headers=HEADERS, resp_body={"ok": True})], HOST))
    assert "body" not in source
"""A run described as data.

The contract under test: a recipe that the capture cannot satisfy is refused
*before any request is sent*, naming everything it couldn't resolve rather than
one gap at a time partway through.
"""
import json

import pytest

from conftest import Loopback, make_flow
from mimic import Session
from mimic.errors import RecipeError
from mimic.recipes import Recipe
from mimic.sources import endpoints

HOST = "api.example.com"
HEADERS = [["Authorization", "Bearer t"], ["User-Agent", "MyApp/2.1.0"]]


def captured():
    return [
        make_flow(path="/v1/me", headers=HEADERS, resp_body={"id": 7}),
        make_flow(fid="f2", path="/users/8931", headers=HEADERS,
                  resp_body={"user": {"id": 8931}}),
        make_flow(fid="f3", path="/users/8932", headers=HEADERS,
                  resp_body={"user": {"id": 8932}}),
    ]


def eps():
    return endpoints(captured(), HOST)


def recipe(*steps, **kw):
    data = {"name": "backfill", "host": HOST, "steps": list(steps)}
    data.update(kw)
    return Recipe.from_dict(data)


# ---- the criterion: refused before anything goes out -------------------------
def test_an_unresolvable_endpoint_is_rejected_before_any_request(loopback):
    loopback.route("/v1/me", Loopback.respond({"id": 7}))
    """The step names a path the capture never saw, so the run must not start."""
    r = recipe({"id": "ghost", "method": "GET", "path": "/v1/nothing"})

    with pytest.raises(RecipeError) as exc:
        r.run(eps(), sessions={HOST: Session(loopback.base_url, {})})

    assert "never saw GET /v1/nothing" in str(exc.value)
    assert loopback.calls == [], "no request may leave before the recipe is valid"


def test_rejection_happens_even_when_other_steps_are_fine(loopback):
    loopback.route("/v1/me", Loopback.respond({"id": 7}))
    r = recipe(
        {"id": "me", "method": "GET", "path": "/v1/me"},
        {"id": "ghost", "method": "GET", "path": "/v1/nothing"},
    )
    with pytest.raises(RecipeError):
        r.run(eps(), sessions={HOST: Session(loopback.base_url, {})})
    assert loopback.calls == []


def test_every_unresolvable_thing_is_reported_at_once(loopback):
    """One round trip to find all the gaps, not one per failed run."""
    r = recipe(
        {"id": "ghost", "method": "GET", "path": "/v1/nothing"},
        {"id": "wrongverb", "method": "DELETE", "path": "/v1/me"},
        {"id": "novalue", "method": "GET", "path": "/users/{id}"},
    )
    with pytest.raises(RecipeError) as exc:
        r.check(eps())

    assert len(exc.value.problems) == 3
    text = str(exc.value)
    assert "/v1/nothing" in text and "DELETE /v1/me" in text and "'id'" in text


def test_a_path_parameter_with_no_value_is_reported_by_name():
    r = recipe({"id": "user", "method": "GET", "path": "/users/{id}"})
    _, problems = r.resolve(eps())
    assert len(problems) == 1
    assert "no value for 'id'" in problems[0]


def test_a_path_parameter_the_endpoint_did_not_declare_is_still_caught():
    """Defensive, and reachable: an endpoint whose `path` carries a template its
    own `path_params` forgot. Sending `{id}` verbatim would be worse."""
    stale = [{"method": "GET", "path": "/users/{id}", "path_params": [],
              "status": 200, "literal_paths": ["/users/{id}"],
              "query": "", "request_body": "", "response_body": "",
              "response_shape": {}}]
    r = recipe({"id": "u", "method": "GET", "path": "/users/{id}"})
    _, problems = r.resolve(stale)
    assert any("no value for 'id'" in p for p in problems)


def test_a_parameter_is_named_once_even_when_both_checks_see_it():
    r = recipe({"id": "u", "method": "GET", "path": "/users/{id}"})
    _, problems = r.resolve(eps())
    assert len(problems) == 1
    assert problems[0].count("'id'") == 1


def test_a_recipe_with_no_steps_says_so():
    _, problems = recipe().resolve(eps())
    assert any("no steps" in p for p in problems)


def test_duplicate_step_ids_are_reported():
    r = recipe({"id": "me", "method": "GET", "path": "/v1/me"},
               {"id": "me", "method": "GET", "path": "/v1/me"})
    _, problems = r.resolve(eps())
    assert any("duplicate id" in p for p in problems)


def test_concurrency_beyond_one_is_reported_rather_than_ignored():
    """The runner is sequential. Accepting `concurrency: 8` and quietly running
    one at a time would look like it worked."""
    r = recipe({"id": "me", "method": "GET", "path": "/v1/me"}, concurrency=8)
    _, problems = r.resolve(eps())
    assert any("sequential" in p for p in problems)


# ---- a recipe the capture can satisfy runs ----------------------------------
def test_a_good_recipe_runs_through_the_runner(loopback):
    loopback.route("/v1/me", Loopback.respond({"id": 7}))
    loopback.route("/users/8931", Loopback.respond({"user": {"id": 8931}}))
    r = recipe({"id": "me", "method": "GET", "path": "/v1/me"},
               {"id": "user", "method": "GET", "path": "/users/{id}",
                "values": {"id": 8931}})

    run = r.run(eps(), sessions={HOST: Session(loopback.base_url, {})})

    assert run.ok and run.results == {"me": {"id": 7},
                                      "user": {"user": {"id": 8931}}}
    assert loopback.paths() == ["/v1/me", "/users/8931"]


def test_steps_run_in_the_order_the_recipe_lists_them():
    r = recipe({"id": "b", "method": "GET", "path": "/users/{id}",
                "values": {"id": 8931}},
               {"id": "a", "method": "GET", "path": "/v1/me"})
    queue, problems = r.resolve(eps())
    assert problems == []
    assert [t.id for t in queue.pending] == ["b", "a"]


def test_the_templated_path_is_filled_with_the_given_value():
    r = recipe({"id": "u", "method": "GET", "path": "/users/{id}",
                "values": {"id": 8932}})
    queue, _ = r.resolve(eps())
    assert queue.pending[0].path == "/users/8932"


def test_a_step_failing_does_not_end_the_run(loopback):
    loopback.route("/v1/me", Loopback.respond({"id": 7}))
    loopback.route("/users/8931", lambda c: (404, {}, b'{"e":1}'))
    r = recipe({"id": "ok", "method": "GET", "path": "/v1/me"},
               {"id": "gone", "method": "GET", "path": "/users/{id}",
                "values": {"id": 8931}})
    run = r.run(eps(), sessions={HOST: Session(loopback.base_url, {})})
    assert [t.id for t, _ in run.finished] == ["ok"]
    assert [t.id for t, _ in run.failed] == ["gone"]
    assert run.pending == ()


# ---- shape of the thing -----------------------------------------------------
def test_a_recipe_round_trips_through_json():
    original = recipe({"id": "me", "method": "GET", "path": "/v1/me"}, rate=5,
                      profile="hinge-iphone")
    again = Recipe.from_dict(json.loads(json.dumps(original.to_dict())))
    assert again.to_dict() == original.to_dict()


def test_a_recipe_can_be_loaded_from_a_file(tmp_path):
    path = tmp_path / "r.json"
    path.write_text(json.dumps({"name": "r", "host": HOST,
                                "steps": [{"method": "GET", "path": "/v1/me"}]}))
    r = Recipe.from_file(str(path))
    assert r.name == "r" and r.steps[0].id == "/v1/me"


def test_a_step_missing_its_path_is_rejected_with_the_name():
    with pytest.raises(RecipeError) as exc:
        Recipe.from_dict({"name": "r", "host": HOST,
                          "steps": [{"id": "broken", "method": "GET"}]})
    assert "broken" in str(exc.value) and "path" in str(exc.value)


def test_a_recipe_that_is_not_an_object_is_rejected():
    with pytest.raises(RecipeError):
        Recipe.from_dict([1, 2, 3])


def test_a_recipe_with_no_profile_says_so():
    with pytest.raises(RecipeError) as exc:
        recipe({"id": "me", "method": "GET", "path": "/v1/me"}).session()
    assert "names no profile" in str(exc.value)
"""Observation: named events, in order, to whoever cares.

Two contracts. The obvious one — events arrive, carrying their payload, in the
order they happened. And the structural one: `events` imports nothing from the
rest of mimic, so subscribing costs nothing and cannot create a cycle.
"""
import ast
import importlib
import inspect

import pytest

from mimic.orchestrate import (
    RATE_LIMITED,
    RUN_FINISHED,
    RUN_STARTED,
    TASK_FAILED,
    TASK_FINISHED,
    TASK_STARTED,
    Emitter,
)


def record(emitter, *names):
    """Subscribe to every event; return the list that accumulates."""
    seen = []
    for name in names:
        emitter.on(name, lambda event, data: seen.append((event, data)))
    return seen


# ---- delivery ----------------------------------------------------------------
def test_a_subscriber_receives_the_event_and_its_payload():
    emitter = Emitter()
    emitter.on(TASK_FINISHED, lambda name, data: seen.append((name, data)))
    seen = []
    emitter.emit(TASK_FINISHED, id="r", host="api")
    assert seen == [("task.finished", {"id": "r", "host": "api"})]


def test_several_subscribers_all_fire_in_subscription_order():
    emitter = Emitter()
    order = []
    emitter.on(RUN_STARTED, lambda n, d: order.append("first"))
    emitter.on(RUN_STARTED, lambda n, d: order.append("second"))
    emitter.emit(RUN_STARTED)
    assert order == ["first", "second"]


def test_events_fire_in_the_order_they_happened():
    emitter = Emitter()
    seen = record(emitter, RUN_STARTED, TASK_STARTED, TASK_FINISHED,
                  TASK_FAILED, RATE_LIMITED, RUN_FINISHED)

    emitter.emit(RUN_STARTED, total=3)
    emitter.emit(TASK_STARTED, id="a")
    emitter.emit(TASK_FINISHED, id="a")
    emitter.emit(TASK_STARTED, id="b")
    emitter.emit(RATE_LIMITED, id="b", retry_after=30)
    emitter.emit(TASK_FAILED, id="b")
    emitter.emit(RUN_FINISHED, finished=1, failed=1, pending=1)

    assert [name for name, _ in seen] == [
        "run.started", "task.started", "task.finished",
        "task.started", "rate_limited", "task.failed", "run.finished",
    ]


def test_a_subscriber_only_hears_its_own_event():
    emitter = Emitter()
    seen = record(emitter, TASK_FINISHED)
    emitter.emit(TASK_STARTED, id="a")
    assert seen == []


def test_emitting_to_nobody_is_harmless():
    emitter = Emitter()
    assert emitter.emit(TASK_FINISHED, id="x") == 0


def test_on_returns_the_callback_so_it_can_be_wrapped():
    emitter = Emitter()

    def watcher(name, data):
        return "called"

    assert emitter.on(RUN_STARTED, watcher) is watcher


def test_listeners_reports_the_attach_count():
    emitter = Emitter()
    assert emitter.listeners(TASK_FINISHED) == 0
    emitter.on(TASK_FINISHED, lambda n, d: None)
    emitter.on(TASK_FINISHED, lambda n, d: None)
    assert emitter.listeners(TASK_FINISHED) == 2


# ---- a broken observer must not take the run down -----------------------------
def test_a_raising_subscriber_is_recorded_not_propagated():
    """Observation isn't why the run exists; it must not be able to end it."""
    emitter = Emitter()
    emitter.on(TASK_FINISHED, lambda n, d: (_ for _ in ()).throw(RuntimeError("x")))
    reached = []
    emitter.on(TASK_FINISHED, lambda n, d: reached.append("later"))

    emitter.emit(TASK_FINISHED, id="a")

    assert reached == ["later"]          # the run carried on
    assert [name for name, _ in emitter.failures] == ["task.finished"]
    assert isinstance(emitter.failures[0][1], RuntimeError)


def test_a_failure_in_one_event_does_not_poison_the_next():
    emitter = Emitter()
    emitter.on(TASK_STARTED, lambda n, d: (_ for _ in ()).throw(ValueError("boom")))
    seen = []
    emitter.on(TASK_FINISHED, lambda n, d: seen.append(d["id"]))
    emitter.emit(TASK_STARTED, id="a")
    emitter.emit(TASK_FINISHED, id="a")
    assert seen == ["a"]
    assert len(emitter.failures) == 1


# ---- the structural boundary --------------------------------------------------
# Read from the source rather than from `sys.modules`: the package facade
# deliberately re-exports all four modules, so an import-order probe would only
# be measuring the facade. What matters is which way each module points.
def _imports_in(module):
    """Every name a module imports, with relative imports marked by leading dots."""
    tree = ast.parse(inspect.getsource(module))
    names = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names += [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            names.append("." * node.level + (node.module or ""))
    return names


def test_the_events_module_has_no_import_statements_at_all():
    """Cheaper than the subprocess check, and it fails at the source."""
    import mimic.orchestrate.events as events

    assert _imports_in(events) == []


@pytest.mark.parametrize("name", ["queue", "ratelimit"])
def test_the_other_leaf_modules_reach_outside_the_package_only(name):
    """`queue` and `ratelimit` may use the standard library; they may not use
    each other, the runner, or `Session`."""
    module = importlib.import_module(f"mimic.orchestrate.{name}")
    assert [n for n in _imports_in(module) if "mimic" in n or n.startswith(".")] == []


def test_only_the_runner_imports_the_package():
    """The one-way arrow, stated once so a future edit that reverses it fails
    here rather than as an import cycle at runtime."""
    module = importlib.import_module("mimic.orchestrate.runner")
    imports = [n for n in _imports_in(module) if n.startswith(".")]
    assert sorted(imports) == ["..errors", ".events", ".queue", ".ratelimit"]
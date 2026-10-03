"""Execution: paced, observable, bounded, and cancellable.

The contract under test, in the order it matters:

- a 429 carrying `Retry-After` delays the next request by that amount, not by a
  schedule the runner made up;
- one task failing never ends the run, and never discards what already worked;
- a run that is cancelled — or interrupted — still comes back with a breakdown
  of what finished, what failed, and what never started.
"""
import pytest

from conftest import FakeClock, Loopback
from mimic import RateLimitError, Session
from mimic.orchestrate import (
    RATE_LIMITED,
    RUN_FINISHED,
    RUN_STARTED,
    TASK_FAILED,
    TASK_FINISHED,
    TASK_STARTED,
    Emitter,
    HostLimiter,
    Runner,
    Task,
    TaskQueue,
)


class StubSession:
    """Stands in for `Session` — the only thing the runner is allowed to call.

    A path mapped to an Exception raises it; anything else is returned as-is.
    Keyed by path, since that's what identifies a request.
    """

    def __init__(self, responses=None):
        self.responses = dict(responses or {})
        self.calls = []

    def request(self, method, path, json=None, params=None):
        self.calls.append((method, path, json, params))
        result = self.responses.get(path, {"ok": path})
        if isinstance(result, Exception):
            raise result
        return result


def paced(rate=100, capacity=100):
    """A limiter far too generous to ever wait on its own, so any delay a test
    sees came from the server."""
    clock = FakeClock()
    return HostLimiter(rate=rate, capacity=capacity, clock=clock,
                       sleep=clock.sleep), clock


def tasks(*ids, host="h"):
    return [Task(i, "GET", f"/{i}", host=host) for i in ids]


# ---- a 429 slows the run by exactly what the server asked for ----------------
def test_a_429_makes_the_next_request_wait_the_servers_retry_after(loopback):
    """The whole reason RateLimitError carries `retry_after`: the server's own
    number beats any schedule this layer could invent."""
    loopback.route("/slow", lambda c: (429, {"Retry-After": "5"}, b"{}"))
    loopback.route("/fine", lambda c: (200, {}, b'{"ok":true}'))
    session = Session(loopback.base_url, {}, attempts=1, sleeper=lambda s: None)
    limiter, clock = paced()

    queue = TaskQueue([
        Task("slow", "GET", "/slow", host="api"),
        Task("fine", "GET", "/fine", host="api"),
    ])
    run = Runner({"api": session}, limiter=limiter).run(queue)

    assert run.failed[0][1].retry_after == 5.0
    # The limiter's own budget (100/s, 100 deep) would never have waited; the
    # only reason the second request was held back is the Retry-After.
    assert clock.now == pytest.approx(5.0)
    assert [t.id for t, _ in run.finished] == ["fine"]


def test_a_429_on_one_host_does_not_delay_another(loopback):
    """A slow API must not spend a fast one's budget."""
    slow = Loopback().start()
    fast = Loopback().start()
    try:
        slow.route("/x", lambda c: (429, {"Retry-After": "30"}, b"{}"))
        slow.route("/x2", lambda c: (200, {}, b"{}"))
        fast.route("/y", Loopback.respond({"fast": True}))
        limiter, clock = paced()
        queue = TaskQueue([
            Task("slow1", "GET", "/x", host="slow"),
            Task("fast", "GET", "/y", host="fast"),
            Task("slow2", "GET", "/x2", host="slow"),
        ])
        run = Runner({
            "slow": Session(slow.base_url, {}, attempts=1, sleeper=lambda s: None),
            "fast": Session(fast.base_url, {}, attempts=1, sleeper=lambda s: None),
        }, limiter=limiter).run(queue)

        assert {t.id for t, _ in run.finished} == {"fast", "slow2"}
        assert clock.now == pytest.approx(30.0)  # only slow waited
    finally:
        slow.stop()
        fast.stop()


def test_a_429_without_a_retry_after_still_completes_the_run(loopback):
    loopback.route("/slow", lambda c: (429, {}, b"{}"))
    loopback.route("/fine", lambda c: (200, {}, b'{"ok":true}'))
    limiter, clock = paced()
    session = Session(loopback.base_url, {}, attempts=1, sleeper=lambda s: None)

    queue = TaskQueue([Task("slow", "GET", "/slow", host="h"),
                       Task("fine", "GET", "/fine", host="h")])
    run = Runner({"h": session}, limiter=limiter).run(queue)

    assert run.failed[0][1].retry_after is None
    assert clock.now == 0.0
    assert [t.id for t, _ in run.finished] == ["fine"]


def test_a_rate_limit_is_announced_before_the_failure_it_causes(loopback):
    """The slowdown is the news; the failure is just the consequence."""
    loopback.route("/slow", lambda c: (429, {"Retry-After": "5"}, b"{}"))
    session = Session(loopback.base_url, {}, attempts=1, sleeper=lambda s: None)
    events = Emitter()
    seen = []
    for name in (RATE_LIMITED, TASK_FAILED):
        events.on(name, lambda n, d: seen.append(n))

    Runner({"h": session}, limiter=paced()[0], events=events).run(
        TaskQueue([Task("slow", "GET", "/slow", host="h")]))

    assert seen == ["rate_limited", "task.failed"]


def test_the_limiter_defers_the_host_that_was_throttled():
    limiter, clock = paced()
    session = StubSession({"/boom": RateLimitError("429", retry_after=12)})
    Runner({"h": session}, limiter=limiter).run(
        TaskQueue([Task("a", "GET", "/boom", host="h")]))
    assert clock.now == 0.0
    limiter.wait("h")
    assert clock.now == pytest.approx(12.0)


# ---- one failure never ends the run ------------------------------------------
def test_a_failing_task_does_not_stop_the_others():
    session = StubSession({"/bad": ValueError("nope")})
    queue = TaskQueue([Task("a", "GET", "/bad", host="h"),
                       Task("b", "GET", "/good", host="h")])

    run = Runner({"h": session}).run(queue)

    assert [t.id for t, _ in run.failed] == ["a"]
    assert [t.id for t, _ in run.finished] == ["b"]
    assert not run.ok


def test_an_unexpected_exception_is_recorded_not_propagated():
    """A run's job is to finish what it can; the exception is kept on the Run so
    nothing is actually lost."""
    session = StubSession({"/bad": RuntimeError("surprise")})
    run = Runner({"h": session}).run(TaskQueue([Task("a", "GET", "/bad", host="h")]))
    assert isinstance(run.failed[0][1], RuntimeError)


def test_a_task_for_a_host_with_no_session_fails_clearly():
    run = Runner({"h": StubSession()}).run(
        TaskQueue([Task("a", "GET", "/x", host="elsewhere")]))
    error = run.failed[0][1]
    assert "elsewhere" in str(error) and "h" in str(error)
    assert run.failed[0][0].id == "a"


def test_a_429_does_not_discard_completed_work():
    session = StubSession({
        "/ok": {"done": True},
        "/slow": RateLimitError("429", retry_after=3),
        "/also_ok": {"done": 2},
    })
    queue = TaskQueue([Task("a", "GET", "/ok", host="h"),
                       Task("b", "GET", "/slow", host="h"),
                       Task("c", "GET", "/also_ok", host="h")])

    run = Runner({"h": session}, limiter=paced()[0]).run(queue)

    assert run.results == {"a": {"done": True}, "c": {"done": 2}}
    assert [t.id for t, _ in run.failed] == ["b"]


def test_the_runner_adds_no_retry_of_its_own():
    """Session owns 'how hard do we try'; the runner calls it exactly once."""
    session = StubSession({"/flaky": RateLimitError("429", retry_after=1)})
    queue = TaskQueue([Task("a", "GET", "/flaky", host="h")])
    Runner({"h": session}, limiter=paced()[0]).run(queue)
    assert len(session.calls) == 1


# ---- the request the runner builds --------------------------------------------
def test_the_task_becomes_the_request_the_runner_sends():
    session = StubSession()
    queue = TaskQueue([Task("r", "POST", "/rec/v2", host="h",
                            json={"x": 1}, params={"p": 2})])
    Runner({"h": session}).run(queue)
    assert session.calls == [("POST", "/rec/v2", {"x": 1}, {"p": 2})]


def test_each_host_goes_to_its_own_session():
    a, b = StubSession(), StubSession()
    queue = TaskQueue([Task("1", "GET", "/a", host="alpha"),
                       Task("2", "GET", "/b", host="beta")])
    Runner({"alpha": a, "beta": b}).run(queue)
    assert a.calls == [("GET", "/a", None, None)]
    assert b.calls == [("GET", "/b", None, None)]


def test_the_limiter_paces_before_the_request_not_after():
    session = StubSession()
    order = []

    class RecordingLimiter:
        def wait(self, host):
            order.append("waited")

        def defer(self, host, seconds):
            order.append("deferred")

    original = session.request

    def traced(*a, **kw):
        order.append("sent")
        return original(*a, **kw)

    session.request = traced
    Runner({"h": session}, limiter=RecordingLimiter()).run(
        TaskQueue([Task("a", "GET", "/a", host="h")]))
    assert order == ["waited", "sent"]


# ---- cancellation --------------------------------------------------------------
def test_cancelling_mid_flight_returns_the_finished_failed_pending_breakdown():
    """The criterion: an interrupted run is described, not merely survived."""
    session = StubSession({"/b": RuntimeError("no")})
    queue = TaskQueue(tasks("a", "b", "c", "d"))
    events = Emitter()
    runner = Runner({"h": session}, events=events)

    def stop_after_b(name, data):
        if data["id"] == "b":
            runner.cancel()

    events.on(TASK_STARTED, stop_after_b)

    run = runner.run(queue)

    assert run.cancelled
    assert [t.id for t, _ in run.finished] == ["a"]
    assert [t.id for t, _ in run.failed] == ["b"]
    assert [t.id for t in run.pending] == ["c", "d"]
    assert not run.ok


def test_a_task_cancelled_while_pacing_is_pending_not_failed():
    """It was never sent, so it is still next — the difference that makes an
    interrupted run resumable."""
    holder = {}

    class CancellingLimiter:
        def wait(self, host):
            holder["runner"].cancel()

        def defer(self, host, seconds):
            pass

    session = StubSession()
    runner = Runner({"h": session}, limiter=CancellingLimiter())
    holder["runner"] = runner
    queue = TaskQueue(tasks("a", "b"))

    run = runner.run(queue)

    assert [t.id for t in run.pending] == ["a", "b"]
    assert run.failed == () and run.finished == ()
    assert session.calls == []          # nothing was sent
    assert run.cancelled


def test_an_interrupt_reports_rather_than_throwing():
    """Ctrl-C ends the run; it does not lose the task that was in flight."""
    session = StubSession()
    queue = TaskQueue(tasks("a", "b", "c"))
    runner = Runner({"h": session})

    def interrupt(*a, **kw):
        raise KeyboardInterrupt

    session.request = interrupt
    run = runner.run(queue)

    assert run.cancelled
    assert run.finished == ()
    assert [t.id for t in run.pending] == ["a", "b", "c"]


def test_an_interrupted_run_accounts_for_every_task():
    """Finished + failed + pending must always cover the whole queue — a task
    that was in flight when the run stopped is pending, not nowhere."""
    session = StubSession()
    queue = TaskQueue(tasks("a", "b", "c"))
    runner = Runner({"h": session})
    calls = {"n": 0}

    def interrupt_second(*a, **kw):
        calls["n"] += 1
        if calls["n"] == 2:
            raise KeyboardInterrupt
        return {"n": calls["n"]}

    session.request = interrupt_second
    run = runner.run(queue)

    accounted = ([t for t, _ in run.finished] + [t for t, _ in run.failed]
                 + list(run.pending))
    assert sorted(t.id for t in accounted) == ["a", "b", "c"]
    assert [t.id for t, _ in run.finished] == ["a"]
    assert [t.id for t in run.pending] == ["b", "c"]


def test_cancelling_before_a_run_does_nothing():
    """The flag is cleared when a run starts; a stale cancel must not silently
    produce an empty run."""
    runner = Runner({"h": StubSession()})
    runner.cancel()
    run = runner.run(TaskQueue(tasks("a")))
    assert [t.id for t, _ in run.finished] == ["a"]
    assert not run.cancelled


def test_a_cancelled_run_still_reports_its_totals():
    events = Emitter()
    runner = Runner({"h": StubSession()}, events=events)
    events.on(RUN_STARTED, lambda n, d: runner.cancel())
    seen = []
    events.on(RUN_FINISHED, lambda n, d: seen.append(d))
    run = runner.run(TaskQueue(tasks("a", "b")))
    assert seen == [{"finished": 0, "failed": 0, "pending": 2,
                     "cancelled": True}]
    assert run.cancelled
    assert run.ok               # cancelling is not the same as failing


def test_the_pending_tasks_are_the_ones_never_started():
    """Not merely 'not finished' — the report has to say they were never sent."""
    sent = []

    class CancellingLimiter:
        def wait(self, host):
            return None

        def defer(self, host, seconds):
            return None

    session = StubSession()
    original = session.request

    def traced(*a, **kw):
        sent.append(a[1])
        return original(*a, **kw)

    session.request = traced
    events = Emitter()
    runner = Runner({"h": session}, limiter=CancellingLimiter(), events=events)
    events.on(TASK_STARTED, lambda n, d: runner.cancel())
    run = runner.run(TaskQueue(tasks("a", "b")))
    assert sent == ["/a"]        # 'a' started; nothing after it ever did
    assert [t.id for t in run.pending] == ["b"]
    assert [t.id for t, _ in run.finished] == ["a"]


def test_a_task_cancelled_while_pacing_is_never_announced_as_started():
    """`task.started` means a request is going out. A task held back by a
    cooldown never emits it, so a subscriber's view matches the report."""
    events = Emitter()
    holder = {}

    class CancellingLimiter:
        def wait(self, host):
            holder["runner"].cancel()

        def defer(self, host, seconds):
            pass

    runner = Runner({"h": StubSession()}, limiter=CancellingLimiter(),
                    events=events)
    holder["runner"] = runner
    started = []
    events.on(TASK_STARTED, lambda n, d: started.append(d["id"]))

    run = runner.run(TaskQueue(tasks("a")))

    assert started == []
    assert [t.id for t in run.pending] == ["a"]
    assert run.finished == () and run.failed == ()


# ---- events -------------------------------------------------------------------
def test_events_fire_in_order_for_a_real_run(loopback):
    """run → task → task → run, with nothing reordering or dropped."""
    loopback.route("/ok", Loopback.respond({"ok": True}))
    loopback.route("/bad", lambda c: (429, {"Retry-After": "1"}, b"{}"))
    limiter, _ = paced()
    session = Session(loopback.base_url, {}, attempts=1, sleeper=lambda s: None)
    events = Emitter()
    seen = []
    for name in (RUN_STARTED, TASK_STARTED, TASK_FINISHED, TASK_FAILED,
                 RATE_LIMITED, RUN_FINISHED):
        events.on(name, lambda n, d: seen.append(n))

    Runner({"h": session}, limiter=limiter, events=events).run(
        TaskQueue([Task("good", "GET", "/ok", host="h"),
                   Task("bad", "GET", "/bad", host="h")]))

    assert seen == [
        "run.started",
        "task.started", "task.finished",
        "task.started", "rate_limited", "task.failed",
        "run.finished",
    ]


def test_a_subscriber_can_watch_without_touching_the_runner():
    events = Emitter()
    seen = []
    events.on(TASK_FINISHED, lambda n, d: seen.append(d["id"]))
    Runner({"h": StubSession()}, events=events).run(TaskQueue(tasks("a", "b")))
    assert seen == ["a", "b"]


def test_run_started_reports_the_size_of_the_run():
    events = Emitter()
    seen = {}
    events.on(RUN_STARTED, lambda n, d: seen.update(d))
    Runner({"h": StubSession()}, events=events).run(TaskQueue(tasks("a", "b", "c")))
    assert seen == {"total": 3}


def test_an_empty_run_is_still_a_report():
    run = Runner({}).run(TaskQueue())
    assert (run.finished, run.failed, run.pending) == ((), (), ())
    assert run.ok


# ---- defaults -----------------------------------------------------------------
def test_a_runner_with_no_limiter_or_emitter_just_works():
    runner = Runner({"h": StubSession()})
    assert runner.limiter is not None and runner.events is not None
    run = runner.run(TaskQueue(tasks("a")))
    assert [t.id for t, _ in run.finished] == ["a"]


def test_a_supplied_limiter_and_emitter_are_the_ones_used():
    limiter, events = paced()[0], Emitter()
    runner = Runner({}, limiter=limiter, events=events)
    assert runner.limiter is limiter and runner.events is events


def test_the_sessions_mapping_is_copied_not_held():
    """A caller mutating their dict afterwards must not retarget a run."""
    sessions = {"h": StubSession()}
    runner = Runner(sessions)
    sessions["h"] = None
    assert runner.sessions["h"] is not None
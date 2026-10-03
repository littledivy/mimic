"""The work ledger: what is pending, and what became of it.

The contract under test: a task ends in exactly one of finished, failed, or
pending, and `pending` really means "never started" — which is what makes an
interrupted run resumable rather than merely reportable.
"""
import pytest

from mimic.orchestrate import Run, Task, TaskQueue


def tasks(*ids, host="h"):
    return [Task(i, "GET", f"/{i}", host=host) for i in ids]


# ---- order -------------------------------------------------------------------
def test_tasks_leave_in_the_order_they_were_added():
    q = TaskQueue(tasks("a", "b", "c"))
    assert [t.id for t in q.pending] == ["a", "b", "c"]
    assert [q.take().id for _ in range(3)] == ["a", "b", "c"]


def test_a_queue_starts_empty_and_falsy():
    q = TaskQueue()
    assert len(q) == 0
    assert not q
    assert q.take() is None


def test_len_counts_what_is_left_not_the_whole_run():
    q = TaskQueue(tasks("a", "b", "c"))
    q.complete(q.take(), {"ok": 1})
    assert len(q) == 2


def test_a_queue_with_work_left_is_truthy():
    q = TaskQueue(tasks("a", "b"))
    assert q
    q.complete(q.take(), None)
    assert q                        # 'b' is still waiting
    q.complete(q.take(), None)
    assert not q


def test_extend_preserves_order():
    q = TaskQueue()
    q.extend(tasks("a", "b"))
    q.extend(tasks("c"))
    assert [t.id for t in q.pending] == ["a", "b", "c"]


# ---- every task lands in exactly one place ------------------------------------
def test_a_taken_task_leaves_the_pending_queue():
    q = TaskQueue(tasks("a", "b"))
    task = q.take()
    assert task not in q.pending
    assert len(q) == 1


def test_completing_records_the_result_against_its_task():
    q = TaskQueue(tasks("a"))
    task = q.take()
    q.complete(task, {"users": []})
    assert q.finished == ((task, {"users": []}),)
    assert q.failed == ()


def test_failing_records_the_error_against_its_task():
    q = TaskQueue(tasks("a"))
    task = q.take()
    q.fail(task, ValueError("nope"))
    stored_task, error = q.failed[0]
    assert stored_task is task
    assert isinstance(error, ValueError)


def test_finished_and_failed_stay_separate_and_ordered():
    q = TaskQueue(tasks("a", "b", "c"))
    a, b, c = q.take(), q.take(), q.take()
    q.complete(a, 1)
    q.fail(b, RuntimeError("x"))
    q.complete(c, 3)
    assert [t.id for t, _ in q.finished] == ["a", "c"]
    assert [t.id for t, _ in q.failed] == ["b"]


def test_two_tasks_may_share_an_id():
    """Results are filed against the task object, not a key, so a duplicated id
    is not a collision."""
    q = TaskQueue([Task("same", "GET", "/one", host="h"),
                   Task("same", "GET", "/two", host="h")])
    first, second = q.take(), q.take()
    q.complete(first, "one")
    q.complete(second, "two")
    assert [r for _, r in q.finished] == ["one", "two"]


# ---- release: cancelled is not failed ----------------------------------------
def test_a_released_task_returns_to_the_front():
    q = TaskQueue(tasks("a", "b", "c"))
    task = q.take()
    q.release(task)
    assert [t.id for t in q.pending] == ["a", "b", "c"]
    assert q.failed == ()
    assert q.finished == ()


def test_a_released_task_is_taken_again_first():
    q = TaskQueue(tasks("a", "b"))
    q.release(q.take())
    assert q.take().id == "a"


def test_pending_is_a_snapshot_not_a_live_view():
    q = TaskQueue(tasks("a"))
    snapshot = q.pending
    q.take()
    assert len(snapshot) == 1
    assert len(q.pending) == 0


# ---- the report this feeds ----------------------------------------------------
def test_a_run_over_the_ledger_adds_up():
    q = TaskQueue(tasks("a", "b", "c", "d"))
    q.complete(q.take(), "A")
    q.fail(q.take(), ValueError("B"))
    run = Run(q.finished, q.failed, q.pending)
    assert (len(run.finished), len(run.failed), len(run.pending)) == (1, 1, 2)


def test_a_run_is_ok_when_only_pending_or_cancelled():
    assert Run(pending=tasks("a")).ok
    assert Run(finished=[("a", 1)], cancelled=True).ok


def test_a_run_is_not_ok_when_anything_failed():
    assert not Run(failed=[("a", ValueError())]).ok


def test_run_results_are_keyed_by_task_id():
    q = TaskQueue(tasks("a", "b"))
    a, b = q.take(), q.take()
    q.complete(a, {"n": 1})
    q.complete(b, {"n": 2})
    assert Run(q.finished, q.failed, q.pending).results == {"a": {"n": 1},
                                                            "b": {"n": 2}}


def test_run_repr_says_what_happened():
    q = TaskQueue(tasks("a", "b", "c"))
    q.complete(q.take(), None)
    run = Run(q.finished, q.failed, q.pending, cancelled=True)
    assert repr(run) == "<Run finished=1 failed=0 pending=2 cancelled=True>"


def test_a_task_carries_only_what_the_runner_needs():
    """No open-ended kwargs: a task has to stay reviewable."""
    task = Task("r", "POST", "/rec", host="api", json={"x": 1}, params={"p": 2})
    assert (task.id, task.method, task.path, task.host) == ("r", "POST", "/rec",
                                                           "api")
    assert (task.json, task.params) == ({"x": 1}, {"p": 2})
    with pytest.raises(TypeError):
        Task("r", "GET", "/x", host="h", timeout=1)
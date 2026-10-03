"""What work is outstanding, and what happened to it.

A run is a sequence of tasks, and every task has to end up in exactly one of
four states — finished, failed, still pending, or taken-and-put-back. Keeping
that ledger in one place is what makes an interrupted run reportable instead of
merely fatal: whoever needs the breakdown asks this object.

    queue = TaskQueue([Task("recs", "GET", "/rec/v2", host="api.example.com")])
    while (task := queue.take()) is not None:
        queue.complete(task, body)   # or .fail(task, exc)

Order is insertion order. Nothing here is concurrent, and a rate limiter with
its own ordering opinions is a later problem that should arrive with evidence
that it is needed.
"""
from collections import deque
from dataclasses import dataclass


@dataclass(frozen=True)
class Task:
    """One request to make, and the name its result will be filed under.

    Deliberately narrow: a method, a path, the session that should send it, and
    a body. An open-ended `**kwargs` would make every task unreviewable, and
    the runner has no business carrying per-task policy anyway — that belongs
    to whatever built the task.
    """

    id: str
    method: str
    path: str
    host: str = ""
    json: object = None
    params: object = None


class TaskQueue:
    """The ledger. Owns pending order and the outcome of everything taken.

    Results are stored as `(task, outcome)` pairs rather than keyed by id, so
    two tasks may share an id — nothing in here needs them to be unique.
    """

    def __init__(self, tasks=()):
        self._pending = deque()
        self._finished = []
        self._failed = []
        for task in tasks:
            self.add(task)

    # -- filling --------------------------------------------------------------
    def add(self, task):
        """Queue `task` after everything already waiting. Returns it."""
        self._pending.append(task)
        return task

    def extend(self, tasks):
        """Queue several, preserving their order."""
        for task in tasks:
            self.add(task)
        return self

    # -- draining -------------------------------------------------------------
    def take(self):
        """The next task, or None when there is nothing left to start.

        Taking a task does not decide its fate; exactly one of `complete`,
        `fail`, or `release` must follow.
        """
        return self._pending.popleft() if self._pending else None

    def release(self, task):
        """Put a taken task back at the front: it never ran, and nothing
        behind it did either, so it is still genuinely next.

        This is the difference between "cancelled" and "failed" in a report:
        a task returned to the queue is one you can pick up again.
        """
        self._pending.appendleft(task)

    def complete(self, task, result):
        """File a task's result."""
        self._finished.append((task, result))

    def fail(self, task, error):
        """File a task's failure, keeping the exception for the report."""
        self._failed.append((task, error))

    # -- reading --------------------------------------------------------------
    @property
    def pending(self):
        """Still waiting, in the order they will be taken. Never started."""
        return tuple(self._pending)

    @property
    def finished(self):
        """`(task, result)` for everything that came back."""
        return tuple(self._finished)

    @property
    def failed(self):
        """`(task, error)` for everything that didn't."""
        return tuple(self._failed)

    def __len__(self):
        """How many tasks have yet to start — not the whole run."""
        return len(self._pending)

    def __bool__(self):
        return bool(self._pending)


__all__ = ["Task", "TaskQueue"]
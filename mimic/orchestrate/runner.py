"""Execution. The one place in mimic that calls `Session` on a schedule.

    queue = TaskQueue([Task("recs", "GET", "/rec/v2", host="api.example.com")])
    runner = Runner({"api.example.com": session})
    run = runner.run(queue)
    run.ok, len(run.finished), len(run.failed), len(run.pending)

Three things this is careful about, in order of how often they bite:

- **It adds no retry policy.** `Session` already has a budget, backoff, and an
  error taxonomy. This module's only response to a failure is to record it and
  move on, so there is exactly one place where "how hard do we try" is decided.
- **A rate limit slows the run, it doesn't end it.** `RateLimitError` carries
  the server's own `Retry-After`; that number goes straight to the limiter and
  nothing is discarded. A run of ten thousand tasks that hits one 429 keeps its
  nine thousand nine hundred and ninety-nine.
- **It always reports.** Cancelled, interrupted, or finished, `run` returns
  what came back, what didn't, and what never started. A traceback alone tells
  you where it stopped, not what you still have.

`runner` is the only module here that imports the other three; it is the seam,
and they stay unaware of it.
"""
from ..errors import MimicError, RateLimitError
from .events import (
    RATE_LIMITED,
    RUN_FINISHED,
    RUN_STARTED,
    TASK_FAILED,
    TASK_FINISHED,
    TASK_STARTED,
    Emitter,
)
from .queue import Task, TaskQueue
from .ratelimit import HostLimiter


class Run:
    """What a run produced. Always complete, however it ended.

    `finished` and `failed` carry the task alongside its outcome, because
    "something succeeded" is not actionable — knowing *which* is.
    """

    def __init__(self, finished=(), failed=(), pending=(), cancelled=False):
        self.finished = tuple(finished)
        self.failed = tuple(failed)
        self.pending = tuple(pending)
        self.cancelled = cancelled

    @property
    def ok(self):
        """True when nothing failed. Cancellation is not failure."""
        return not self.failed

    @property
    def results(self):
        """`{task.id: result}` for everything that came back."""
        return {task.id: result for task, result in self.finished}

    def __repr__(self):
        return (f"<Run finished={len(self.finished)} failed={len(self.failed)} "
                f"pending={len(self.pending)} cancelled={self.cancelled}>")


class Runner:
    """Drains a `TaskQueue` through per-host `Session`s.

    `sessions` maps a task's host to the session that should send it; a task
    naming a host with no session fails with a message saying so, rather than
    being silently dropped.

    `cancel()` is safe to call from another thread or from a subscriber, and
    stops the run after the task in flight. Cancelling before `run()` does
    nothing — the flag is cleared when a run starts.
    """

    def __init__(self, sessions, limiter=None, events=None):
        self.sessions = dict(sessions)
        self.limiter = limiter if limiter is not None else HostLimiter()
        self.events = events if events is not None else Emitter()
        self._cancelled = False

    def cancel(self):
        """Ask the run to stop after the current task."""
        self._cancelled = True

    def run(self, queue):
        """Run every pending task. Always returns a `Run`."""
        self._cancelled = False
        try:
            self._drain(queue)
        except KeyboardInterrupt:
            # Ctrl-C is a cancellation like any other: report the breakdown
            # rather than throwing away everything that already succeeded.
            self._cancelled = True
        return self._report(queue)

    # ---- internals ----------------------------------------------------------
    def _drain(self, queue):
        self.events.emit(RUN_STARTED, total=len(queue))
        while not self._cancelled:
            task = queue.take()
            if task is None:
                return
            try:
                self._execute(queue, task)
            except BaseException:
                # Whatever just ended this task — Ctrl-C, SystemExit — it did
                # not finish, so it goes back in the queue rather than falling
                # out of the report entirely. Re-raised: the run still stops.
                queue.release(task)
                raise

    def _execute(self, queue, task):
        """Send one task and file it under exactly one outcome."""
        session = self.sessions.get(task.host)
        if session is None:
            self._fail(queue, task, MimicError(
                f"no Session for host {task.host!r} — this runner has "
                f"{sorted(self.sessions)}"
            ))
            return

        self.limiter.wait(task.host)
        if self._cancelled:
            # Cancelled while pacing. Nothing was sent, so it is still next,
            # not failed — the difference the caller cares about.
            queue.release(task)
            return

        # Announced only once we are actually sending, so a subscriber that
        # never sees task.started knows the task was never sent.
        self.events.emit(TASK_STARTED, id=task.id, host=task.host,
                         method=task.method, path=task.path)
        try:
            result = session.request(task.method, task.path, json=task.json,
                                      params=task.params)
        except RateLimitError as exc:
            # Session already spent its own retry budget; the only new
            # information is how long the server wants us gone.
            self.limiter.defer(task.host, exc.retry_after)
            self.events.emit(RATE_LIMITED, id=task.id, host=task.host,
                             retry_after=exc.retry_after)
            self._fail(queue, task, exc)
            return
        except Exception as exc:
            # One task's failure is that task's news. Catching here rather than
            # letting it out is the entire point of a run; the exception is kept
            # on the Run so nothing is actually lost.
            self._fail(queue, task, exc)
            return

        queue.complete(task, result)
        self.events.emit(TASK_FINISHED, id=task.id, host=task.host)

    def _fail(self, queue, task, error):
        queue.fail(task, error)
        self.events.emit(TASK_FAILED, id=task.id, host=task.host,
                         error=error, error_type=type(error).__name__)

    def _report(self, queue):
        run = Run(queue.finished, queue.failed, queue.pending, self._cancelled)
        self.events.emit(RUN_FINISHED, finished=len(run.finished),
                         failed=len(run.failed), pending=len(run.pending),
                         cancelled=run.cancelled)
        return run


__all__ = ["Runner", "Run", "Task", "TaskQueue", "HostLimiter", "Emitter"]
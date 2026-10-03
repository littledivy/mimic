"""Progress you can subscribe to, without getting in the way of the work.

    emitter = Emitter()
    emitter.on(TASK_FINISHED, lambda name, data: print(data["id"], "done"))
    runner = Runner(sessions, events=emitter)
    runner.run(queue)

This module imports nothing from the rest of mimic — not the runner, not the
queue, not the limiter. That is the whole design constraint, and it is worth
stating plainly because it is what keeps the dependency arrow pointing one way:
the runner knows it can be watched; a watcher never has to know what is
watching it.

Events are named strings rather than a type hierarchy because the useful set is
small, stable, and already documented by the constants below. A subscriber that
doesn't care about the payload ignores it; one that does reads `data`.
"""


#: A run began. `total` is how many tasks were pending when it started.
RUN_STARTED = "run.started"

#: A run ended, whether it completed, was cancelled, or was interrupted.
#: `finished`/`failed`/`pending` are counts; `cancelled` is a bool.
RUN_FINISHED = "run.finished"

#: A task is about to be sent: `id`, `host`, `method`, `path`.
TASK_STARTED = "task.started"

#: A task returned a body: `id`, `host`.
TASK_FINISHED = "task.finished"

#: A task failed: `id`, `host`, `error`. The run continues.
TASK_FAILED = "task.failed"

#: The server asked this host to back off: `id`, `host`, `retry_after`. This is
#: emitted before TASK_FAILED — a rate limit that outlived Session's retry
#: budget is both a slowdown and a failure, and the slowdown is the news.
RATE_LIMITED = "rate_limited"


class Emitter:
    """Named events to interested callbacks. No types, no inheritance.

    A subscriber that raises does not take the run down with it: observation is
    not the reason the run exists. Its failure is recorded in `failures`
    instead, because silently swallowing a broken callback is how you end up
    debugging the wrong thing for an afternoon.
    """

    def __init__(self):
        self._subscribers = {}
        #: `(event_name, exception)` for every subscriber call that raised.
        self.failures = []

    def on(self, name, fn):
        """Subscribe `fn(name, data)` to the event `name`. Returns `fn`."""
        self._subscribers.setdefault(name, []).append(fn)
        return fn

    def emit(self, name, **data):
        """Deliver `name` to its subscribers. Never raises."""
        for fn in self._subscribers.get(name, ()):
            try:
                fn(name, data)
            except Exception as exc:  # a broken observer is not a broken run
                self.failures.append((name, exc))
        return len(self._subscribers.get(name, ()))

    def listeners(self, name):
        """How many subscribers are attached to `name`."""
        return len(self._subscribers.get(name, ()))


__all__ = [
    "Emitter",
    "RUN_STARTED",
    "RUN_FINISHED",
    "TASK_STARTED",
    "TASK_FINISHED",
    "TASK_FAILED",
    "RATE_LIMITED",
]
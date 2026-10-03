"""Running many captured calls, paced, observable, and cancellable.

Four modules, one owner each, depending in one direction only:

    events.py     what happened            imports nothing from mimic
    queue.py      what is left to do       imports nothing from mimic
    ratelimit.py  how fast to go           imports nothing from mimic
    runner.py     doing it                 composes the three

    from mimic.orchestrate import Runner, Task, TaskQueue

The first three know nothing about each other or about `Session`, which is what
keeps them testable on their own and keeps the observer from depending on the
observed. Only `runner` talks to a `Session`, so "what a run does" has exactly
one definition.
"""
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
from .ratelimit import HostLimiter, TokenBucket
from .runner import Run, Runner

__all__ = [
    "Runner",
    "Run",
    "Task",
    "TaskQueue",
    "HostLimiter",
    "TokenBucket",
    "Emitter",
    "RUN_STARTED",
    "RUN_FINISHED",
    "TASK_STARTED",
    "TASK_FINISHED",
    "TASK_FAILED",
    "RATE_LIMITED",
]
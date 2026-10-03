"""A run described as data instead of Python.

    {
      "name": "backfill",
      "host": "api.example.com",
      "profile": "hinge-iphone",
      "rate": 5,
      "steps": [
        {"id": "me",   "method": "GET", "path": "/v1/me"},
        {"id": "user", "method": "GET", "path": "/users/{id}",
         "values": {"id": 8931}}
      ]
    }

    from mimic.recipes import Recipe
    Recipe.from_file("backfill.json").run(endpoints)

The point of a recipe is that the whole run is checkable before any of it runs.
A step naming an endpoint the capture never saw, or a templated path with no
value for one of its parameters, is knowable from the capture alone — so
`resolve` reports *every* such gap at once and `run` refuses to send anything
until they are gone. A run that fails on step forty with one line of output is
the thing this exists to prevent.

Everything after resolution is the Layer 4 runner: pacing per host, progress
events, and a finished/failed/pending breakdown on cancellation.
"""
import json

from .errors import MimicError, RecipeError
from .orchestrate import HostLimiter, Runner, Task, TaskQueue
from .session import Session


class Step:
    """One endpoint to call, with the values its path parameters need."""

    __slots__ = ("id", "method", "path", "values")

    def __init__(self, id, method, path, values=None):
        self.id = id
        self.method = (method or "GET").upper()
        self.path = path
        self.values = dict(values or {})

    @classmethod
    def from_dict(cls, data):
        if not isinstance(data, dict):
            raise RecipeError(f"a step must be an object, got {type(data).__name__}")
        missing = [k for k in ("method", "path") if not data.get(k)]
        if missing:
            raise RecipeError(
                f"step {data.get('id', '<unnamed>')!r} is missing "
                f"{' and '.join(missing)}"
            )
        return cls(data.get("id") or data["path"], data["method"], data["path"],
                   data.get("values"))

    def __repr__(self):
        return f"<Step {self.id} {self.method} {self.path}>"


class Recipe:
    """Endpoints to call, how fast, and which saved profile to run as."""

    def __init__(self, name="", host="", profile="", rate=None,
                 concurrency=1, steps=()):
        self.name = name
        self.host = host
        self.profile = profile
        self.rate = rate
        self.concurrency = int(concurrency or 1)
        self.steps = [Step.from_dict(s) if isinstance(s, dict) else s
                      for s in steps]

    # ---- parsing ------------------------------------------------------------
    @classmethod
    def from_dict(cls, data):
        if not isinstance(data, dict):
            raise RecipeError(f"a recipe must be a JSON object, got "
                              f"{type(data).__name__}")
        try:
            return cls(name=data.get("name", ""), host=data.get("host", ""),
                       profile=data.get("profile", ""), rate=data.get("rate"),
                       concurrency=data.get("concurrency", 1),
                       steps=data.get("steps") or ())
        except MimicError as exc:
            raise RecipeError(f"recipe {data.get('name', '<unnamed>')!r}: {exc}")

    @classmethod
    def from_file(cls, path):
        with open(path) as fh:
            return cls.from_dict(json.load(fh))

    def to_dict(self):
        return {"name": self.name, "host": self.host, "profile": self.profile,
                "rate": self.rate, "concurrency": self.concurrency,
                "steps": [{"id": s.id, "method": s.method, "path": s.path,
                           "values": dict(s.values)} for s in self.steps]}

    # ---- checking -----------------------------------------------------------
    def resolve(self, endpoints):
        """Match every step against the capture.

        Returns ``(queue, problems)``. `queue` is only meaningful when
        `problems` is empty — an unresolvable step contributes a problem, never
        a half-built task that would blow up mid-run.
        """
        known = {}
        for e in endpoints:
            known[(e.get("method", "GET").upper(), e.get("path"))] = e

        problems, queue, seen = [], TaskQueue(), set()
        if not self.steps:
            problems.append("the recipe has no steps")

        for step in self.steps:
            if step.id in seen:
                problems.append(f"step {step.id!r}: duplicate id")
            seen.add(step.id)
            entry = known.get((step.method, step.path))
            if entry is None:
                problems.append(
                    f"step {step.id!r}: the capture never saw "
                    f"{step.method} {step.path}"
                )
                continue
            path, missing = _fill(step, entry.get("path_params") or [])
            if missing:
                problems.append(
                    f"step {step.id!r}: no value for "
                    + ", ".join(f"{p!r} in {step.path!r}" for p in missing)
                )
                continue
            queue.add(Task(step.id, step.method, path, host=self.host))

        if self.concurrency > 1:
            problems.append(
                f"concurrency {self.concurrency} was requested, but the runner is "
                f"sequential — set it to 1 until parallel dispatch lands"
            )
        return queue, problems

    def check(self, endpoints):
        """Resolve and raise unless everything can be answered. Returns the queue."""
        queue, problems = self.resolve(endpoints)
        if problems:
            raise RecipeError(
                f"recipe {self.name or '<unnamed>'!r} cannot run as written:\n  - "
                + "\n  - ".join(problems),
                problems=problems,
            )
        return queue

    # ---- running ------------------------------------------------------------
    def session(self, **kw):
        """The Session this recipe runs as: its saved profile, or a clear error."""
        if not self.profile:
            raise RecipeError(
                f"recipe {self.name or '<unnamed>'!r} names no profile — set "
                f'"profile" to one saved with `mimic profile save`, or pass a '
                f"session to run(sessions=...)"
            )
        from .vault import Vault  # lazy: keeps the optional extra off this path
        return Session.from_profile(self.profile, Vault(), **kw)

    def run(self, endpoints, sessions=None, **kw):
        """Resolve, then execute with the Layer 4 runner.

        Raises `RecipeError` — before any request is sent — if the recipe names
        anything the capture cannot answer.
        """
        queue = self.check(endpoints)
        if sessions is None:
            sessions = {self.host: self.session()}
        kw.setdefault("limiter", HostLimiter(rate=self.rate) if self.rate else None)
        return Runner(sessions, **kw).run(queue)

    def __repr__(self):
        return f"<Recipe {self.name or '<unnamed>'} {len(self.steps)} steps>"


def _fill(step, path_params):
    """Substitute a step's values into its templated path.

    Returns ``(path, missing)``; `missing` names parameters with no value, which
    is a reportable gap rather than a `KeyError` halfway through a run.
    """
    path, missing = step.path, []
    for name in path_params:
        if name not in step.values:
            missing.append(name)
        else:
            path = path.replace("{" + name + "}", str(step.values[name]))
    # An endpoint whose `path` carries a template its own `path_params` forgot
    # would otherwise be sent with a literal `{id}` in the URL.
    for part in path.split("/"):
        if part.startswith("{") and part[1:-1] not in missing:
            missing.append(part[1:-1])
    return path, missing


__all__ = ["Recipe", "Step", "RecipeError"]
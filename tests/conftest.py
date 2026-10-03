"""Shared test fixtures: a scriptable loopback HTTP server.

Session's interesting behaviour — cookie rotation, timeouts, retry budgets,
error mapping — only shows up against a real socket, so these tests talk to an
actual server on localhost instead of stubbing the HTTP layer. Stubbing is what
hid the cookie-jar bug in the first place.
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest


def make_flow(host="api.example.com", method="GET", path="/v1/x", req_body=None,
              resp_body=None, status=200, fid="f1", headers=None):
    """Build a mimic flow dict, the shape both capture backends normalize to.

    Bodies default to empty rather than None so tests that only care about
    structure don't have to say so.
    """
    return {
        "id": fid,
        "request": {
            "host": host, "method": method, "path": path, "scheme": "https",
            "port": 443,
            "headers": headers if headers is not None else [["Authorization", "Bearer t"]],
            "content": _encode(req_body),
        },
        "response": {
            "status_code": status, "headers": [],
            "content": _encode(resp_body),
        },
    }


def _encode(body):
    if body is None:
        return b""
    if isinstance(body, bytes):
        return body
    if isinstance(body, str):
        return body.encode()
    return json.dumps(body).encode()


class Call:
    """One request the server received."""

    def __init__(self, method, path, headers, body):
        self.method = method
        self.path = path
        self.headers = headers
        self.body = body

    @property
    def cookie(self):
        return self.headers.get("Cookie")

    def json(self):
        return json.loads(self.body)


class Loopback:
    """A local HTTP server whose responses each test scripts by path.

        lb = Loopback()
        lb.route("/thing", lambda c: (200, {}, b'{"ok":true}'))
        Session(lb.base_url).get("/thing")
    """

    def __init__(self):
        self.calls = []
        self._routes = {}
        self._server = None
        self._thread = None

    # -- scripting -----------------------------------------------------------
    def route(self, path, handler):
        """Register `handler(call) -> (status, headers, body_bytes)` for `path`.

        `headers` values may be str or list[str] for repeated headers.
        """
        self._routes[path] = handler
        return self

    def route_once(self, path, handler, then):
        """Answer `handler` for the first call to `path`, then `then` forever."""
        state = {"n": 0}

        def wrapper(call):
            state["n"] += 1
            return handler(call) if state["n"] == 1 else then(call)

        self._routes[path] = wrapper
        return self

    @staticmethod
    def respond(payload, status=200, headers=None):
        """Build a handler that always answers the same JSON body."""
        body = json.dumps(payload).encode()

        def handler(call):
            return status, headers or {}, body

        return handler

    # -- lifecycle -----------------------------------------------------------
    @property
    def base_url(self):
        host, port = self._server.server_address
        return f"http://127.0.0.1:{port}"

    def start(self):
        outer = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"  # keep-alive, like a real server

            def _dispatch(self):
                path = self.path.split("?")[0]
                body = b""
                length = int(self.headers.get("Content-Length") or 0)
                if length:
                    body = self.rfile.read(length)
                call = Call(self.command, path, self.headers, body)
                outer.calls.append(call)

                handler = outer._routes.get(path)
                if handler is None:
                    status, headers, body = 404, {}, b'{"error":"no route"}'
                else:
                    status, headers, body = handler(call)

                self.send_response(status)
                for key, value in (headers or {}).items():
                    if isinstance(value, (list, tuple)):
                        for item in value:
                            self.send_header(key, item)
                    else:
                        self.send_header(key, value)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)

            do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = _dispatch

            def log_message(self, *args):
                pass  # keep the test output clean

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self):
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None

    # -- assertions ----------------------------------------------------------
    def paths(self):
        return [c.path for c in self.calls]


class RecordingSleeper:
    """Stands in for time.sleep so retry tests run instantly and can assert."""

    def __init__(self):
        self.delays = []

    def __call__(self, seconds):
        self.delays.append(seconds)

    @property
    def total(self):
        return sum(self.delays)


class FakeClock:
    """A monotonic clock that only moves when something sleeps.

    Pacing tests need a clock and a sleep that agree: the limiter reads the
    clock to decide how long to wait, so if sleeping didn't move the clock, a
    test of "waited 0.5s" would hang instead of finishing. Paired, they make an
    assertion about real elapsed time cost no wall-clock time at all.
    """

    def __init__(self, start=0.0):
        self.now = float(start)
        self.sleeps = []

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds

    def advance(self, seconds):
        """Move time without sleeping — the caller was busy elsewhere."""
        self.now += seconds

    def __repr__(self):
        return f"<FakeClock t={self.now} slept={self.sleeps}>"


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def loopback():
    server = Loopback().start()
    try:
        yield server
    finally:
        server.stop()


@pytest.fixture
def sleeper():
    return RecordingSleeper()


# ---- a stand-in mitmweb -----------------------------------------------------
#: How many flows the fake capture advertises. Big enough that "one request per
#: endpoint" is obviously wrong if it comes back.
N_FLOWS = 100


def wire_flow(fid="f1", token=None, host="api.example.com"):
    """A mitmweb `/flows` listing entry: JSON-safe, no bodies.

    The real listing carries metadata only — bodies live behind a separate
    endpoint — so nothing here can hold bytes.
    """
    headers = [["Authorization", token]] if token else []
    return {"id": fid, "request": {"host": host, "method": "GET",
                                   "path": f"/v1/{fid}", "scheme": "https",
                                   "port": 443, "headers": headers},
            "response": {"status_code": 200}}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        server = self.server
        server.hits.append(self.path)
        if self.path.startswith("/flows/dump"):
            status, ctype, body = 200, "application/octet-stream", b"DUMP"
        elif self.path == "/flows":
            body = json.dumps(server.flows).encode()
            status, ctype = 200, "application/json"
        else:
            status, ctype, body = 200, "text/html", b"ok"
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class FakeMitmWeb(ThreadingHTTPServer):
    """Records every request, so cost claims are measurable rather than argued.

    `flows` is mutable: assign to it to simulate newer traffic appearing in a
    running mitmproxy, which is what the cache has to respect.
    """

    daemon_threads = True

    def __init__(self):
        super().__init__(("127.0.0.1", 0), Handler)
        self.hits = []
        self.flows = [wire_flow(f"f{i}") for i in range(N_FLOWS)]

    @property
    def url(self):
        host, port = self.server_address
        return f"http://127.0.0.1:{port}"

    def count(self, needle):
        return len([h for h in self.hits if needle in h])


@pytest.fixture
def mitmweb():
    server = FakeMitmWeb()
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()

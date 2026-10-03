"""Pacing: how fast each host may be asked, and how long after a 429.

A token bucket per host. Each host gets its own bucket, so one API that is
slow or throttling can never spend another API's budget — a run that talks to
three hosts and hits limits on one of them should keep working at full speed
against the other two.

The bucket is the *floor* on pacing, not the whole policy. When a server says
"come back in 30 seconds" in a `Retry-After` header, that is better information
than any schedule this module could invent, so `defer` pins the host until
exactly that moment and the bucket resumes from wherever it was left.

    limiter = HostLimiter(rate=5, capacity=5)
    limiter.wait("api.example.com")          # blocks if the bucket is empty
    limiter.defer("api.example.com", 30)     # a 429 said so

Clock and sleep are injected for the same reason `Session` takes a `sleeper`:
a pacing policy that can only be tested by really waiting is a policy that
doesn't get tested.
"""
import time


#: A leftover smaller than this is arithmetic noise, not credit. At any real
#: rate it is worth far less than a clock tick, and crediting it would ask for a
#: sleep shorter than the clock can express — which never advances, so `take`
#: spins on the last sliver of a token forever.
_TOKEN_EPS = 1e-9


class TokenBucket:
    """`capacity` tokens, refilled at `rate` per second.

    `rate=None` means unlimited — every `take` returns immediately, which is
    what a run with no pacing configured wants.
    """

    def __init__(self, rate, capacity=None, clock=time.monotonic, sleep=time.sleep):
        self.rate = rate
        self.capacity = float(capacity if capacity is not None else rate or 0.0)
        self._clock = clock
        self._sleep = sleep
        self._tokens = self.capacity
        self._updated = clock()
        self._blocked_until = 0.0

    @property
    def limited(self):
        """False when this bucket never makes anyone wait."""
        return self.rate is not None and self.rate > 0

    def _refill(self):
        """Credit the time that has passed. Returns the current time."""
        now = self._clock()
        self._tokens = min(self.capacity,
                           self._tokens + max(0.0, now - self._updated) * self.rate)
        self._updated = now
        return now

    def take(self):
        """Consume one token, blocking until one is available.

        Returns the seconds spent waiting. Waits are re-checked after sleeping,
        so a `defer` that lands mid-wait is honoured rather than waited out.
        """
        if not self.limited:
            return 0.0
        started = self._clock()
        while True:
            now = self._refill()
            if now < self._blocked_until:
                self._sleep(self._blocked_until - now)
                continue
            if self._tokens >= 1.0 - _TOKEN_EPS:
                self._tokens -= 1.0
                if self._tokens < _TOKEN_EPS:
                    self._tokens = 0.0
                return max(0.0, self._clock() - started)
            self._sleep((1.0 - self._tokens) / self.rate)

    def defer(self, seconds):
        """Refuse to admit anything for `seconds` from now.

        Named after the `Retry-After` header, which is where the number should
        have come from. A zero or negative value is ignored: a server sending
        "come back never" is a server sending nonsense, and the run should
        continue at its own pace rather than hang.
        """
        if not self.limited or not seconds or seconds <= 0:
            return
        self._blocked_until = max(self._blocked_until, self._clock() + seconds)


class HostLimiter:
    """One `TokenBucket` per host, created on first use.

    Buckets are independent: `defer` on one host cannot delay any other, which
    is the whole reason this is keyed rather than global.
    """

    def __init__(self, rate=5.0, capacity=None, clock=time.monotonic,
                 sleep=time.sleep):
        self.rate = rate
        self.capacity = capacity
        self._clock = clock
        self._sleep = sleep
        self._buckets = {}

    def bucket(self, host):
        """This host's bucket, made on first request."""
        if host not in self._buckets:
            self._buckets[host] = TokenBucket(
                self.rate, self.capacity, clock=self._clock, sleep=self._sleep
            )
        return self._buckets[host]

    def wait(self, host):
        """Block until `host` may be called again."""
        return self.bucket(host).take()

    def defer(self, host, seconds):
        """Hold `host` off for `seconds`, because it asked us to."""
        return self.bucket(host).defer(seconds)

    @property
    def hosts(self):
        """Every host that has been paced so far."""
        return tuple(sorted(self._buckets))


__all__ = ["TokenBucket", "HostLimiter"]
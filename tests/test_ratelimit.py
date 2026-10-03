"""Pacing: token buckets and the server's own Retry-After.

The contract under test: a host is asked no faster than its bucket allows, one
host's backlog never delays another's, and a `Retry-After` the server sent is
honoured exactly rather than approximated by a schedule.
"""
import pytest

from conftest import FakeClock
from mimic.orchestrate import HostLimiter, TokenBucket


def bucket(rate, capacity=None, clock=None):
    clock = clock or FakeClock()
    return TokenBucket(rate, capacity, clock=clock, sleep=clock.sleep), clock


# ---- a bucket admits exactly N in a window and blocks the N+1 ----------------
def test_a_bucket_admits_exactly_its_capacity_then_blocks(clock):
    """rate 2/s with capacity 2: two requests go out at t=0, the third waits."""
    b, _ = bucket(2, capacity=2, clock=clock)
    took = []
    for _ in range(5):
        b.take()
        took.append(clock.now)
    # Two at t=0, then one every 0.5s. The third request is the one that waits.
    assert took == [0.0, 0.0, 0.5, 1.0, 1.5]


def test_the_n_plus_first_request_waits_exactly_for_one_token(clock):
    b, _ = bucket(2, capacity=2, clock=clock)
    b.take()
    b.take()
    assert clock.now == 0.0          # the window is spent, not blocked
    b.take()
    assert clock.now == pytest.approx(0.5)


@pytest.mark.parametrize("rate", [1.0, 2.0, 5.0, 10.0])
def test_no_window_admits_more_than_its_share(rate):
    """The invariant, stated directly rather than through one example.

    A bucket of capacity C lets up to C requests go out together; past that
    burst, no one-second window may contain more than `rate` requests.
    """
    clock = FakeClock()
    b = TokenBucket(rate, capacity=1, clock=clock, sleep=clock.sleep)
    times = []
    for _ in range(60):
        b.take()
        times.append(clock.now)

    for start in times:
        admitted = sum(1 for t in times if start <= t < start + 1.0)
        assert admitted <= rate + 1


def test_a_bucket_never_credits_more_than_its_capacity(clock):
    """An hour of idling must not buy an hour of requests."""
    b, _ = bucket(1, capacity=2, clock=clock)
    clock.advance(3600)
    b.take()
    b.take()
    assert clock.sleeps == []
    b.take()
    assert clock.sleeps == pytest.approx([1.0])


def test_capacity_defaults_to_one_second_of_tokens(clock):
    b, _ = bucket(3, clock=clock)
    assert b.capacity == 3.0


def test_an_unlimited_bucket_never_makes_anyone_wait(clock):
    b, _ = bucket(None, clock=clock)
    assert b.limited is False
    for _ in range(100):
        assert b.take() == 0.0
    assert clock.sleeps == []


def test_take_reports_how_long_it_waited(clock):
    b, _ = bucket(2, capacity=2, clock=clock)
    assert b.take() == 0.0
    assert b.take() == 0.0
    assert b.take() == pytest.approx(0.5)


# ---- a defer is the server's number, not ours --------------------------------
def test_a_defer_holds_the_bucket_for_exactly_that_long(clock):
    b, _ = bucket(10, capacity=10, clock=clock)
    for _ in range(10):
        b.take()
    b.defer(30)                      # a 429 carrying Retry-After: 30
    b.take()
    assert clock.now == pytest.approx(30.0)


def test_a_defer_is_honoured_when_it_lands_mid_wait(clock):
    """A wait already in progress must be re-checked, not waited out.

    Without the re-check `take` would sleep the second it asked for, return
    early, and hit a host that had meanwhile said "not for another 5s".
    """
    holder, answered = {}, []

    def sleep_then_rate_limit(seconds):
        clock.sleep(seconds)
        if not answered:
            answered.append(True)
            holder["bucket"].defer(5)      # the server answers mid-wait

    b = TokenBucket(1, capacity=1, clock=clock, sleep=sleep_then_rate_limit)
    holder["bucket"] = b
    b.take()                            # immediate: the bucket is full
    b.take()                            # waits, is deferred, waits again
    assert clock.now == pytest.approx(6.0)


def test_a_defer_with_no_value_is_ignored(clock):
    b, _ = bucket(1, capacity=1, clock=clock)
    b.defer(0)
    b.defer(None)
    b.defer(-10)
    b.take()                         # only the token, not the defer
    assert clock.now == 0.0
    b.take()
    assert clock.now == pytest.approx(1.0)


def test_a_later_defer_never_shortens_an_earlier_one(clock):
    b, _ = bucket(10, capacity=1, clock=clock)
    b.take()
    b.defer(30)
    clock.advance(10)
    b.defer(5)                      # a weaker server answer must not win
    b.take()
    assert clock.now == pytest.approx(30.0)


# ---- one host's backlog never spends another's budget ------------------------
def test_buckets_are_keyed_per_host():
    """The reason this class exists: a slow API can't starve a fast one."""
    clock = FakeClock()
    limiter = HostLimiter(rate=1, capacity=1, clock=clock, sleep=clock.sleep)
    limiter.wait("slow.example.com")      # spends that host's only token
    limiter.defer("slow.example.com", 60)  # and it now has a server cooldown

    limiter.wait("fast.example.com")      # a different host, untouched
    assert clock.now == 0.0
    assert limiter.hosts == ("fast.example.com", "slow.example.com")


def test_a_defer_on_one_host_does_not_delay_another(clock):
    limiter = HostLimiter(rate=1, capacity=1, clock=clock, sleep=clock.sleep)
    limiter.defer("throttled.example.com", 30)
    for _ in range(5):
        limiter.wait("fine.example.com")
    # 'fine' was paced by its own 1/s bucket — four seconds for five requests —
    # and not one second of the 30 the other host asked for.
    assert clock.now == pytest.approx(4.0)
    limiter.wait("throttled.example.com")
    assert clock.now == pytest.approx(30.0)


def test_hosts_are_paced_independently(clock):
    limiter = HostLimiter(rate=1, capacity=1, clock=clock, sleep=clock.sleep)
    limiter.wait("a.example.com")
    limiter.wait("a.example.com")
    limiter.wait("b.example.com")
    # 'a' waited for its second token; 'b' had its own and did not.
    assert clock.now == pytest.approx(1.0)


def test_a_bucket_is_created_once_per_host(clock):
    limiter = HostLimiter(rate=1, capacity=1, clock=clock, sleep=clock.sleep)
    first = limiter.bucket("a.example.com")
    assert limiter.bucket("a.example.com") is first


def test_an_unlimited_limiter_is_the_default_shape(clock):
    """A runner with no pacing configured must never block anybody."""
    limiter = HostLimiter(rate=None, clock=clock, sleep=clock.sleep)
    for _ in range(100):
        limiter.wait("anything")
    assert clock.sleeps == []
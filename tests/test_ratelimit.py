"""Arc 11 phase 68 — token bucket + backpressure invariants."""
from __future__ import annotations

import time

import pytest

import ratelimit


@pytest.fixture(autouse=True)
def clean_registry():
    ratelimit.reset_for_test()
    yield
    ratelimit.reset_for_test()


def test_burst_then_deny():
    b = ratelimit.TokenBucket("t", tokens_per_min=60, capacity=5)
    assert sum(1 for _ in range(10) if b.acquire()) == 5


def test_refill_steady_state():
    b = ratelimit.TokenBucket("t", tokens_per_min=600, capacity=3)
    # Drain it
    for _ in range(3):
        assert b.acquire()
    assert not b.acquire()
    # 0.2s at 10/s = 2 tokens — should be able to take both
    time.sleep(0.25)
    assert b.acquire()
    assert b.acquire()
    assert not b.acquire()


def test_record_429_drains_and_halves_rate():
    b = ratelimit.TokenBucket("t", tokens_per_min=600, capacity=10)
    b.record_429()
    st = b.status()
    assert st["tokens"] == 0
    assert st["penalty_active"]
    # After 0.5s at half-rate (300/min = 5/s) we get ~2.5 tokens
    time.sleep(0.5)
    st = b.status()
    assert st["tokens"] >= 2.0
    assert st["tokens"] <= 3.0


def test_registry_dedupe():
    a = ratelimit.get_bucket("lapi")
    b = ratelimit.get_bucket("lapi")
    assert a is b


def test_unknown_bucket_uses_default():
    b = ratelimit.get_bucket("brand.new.upstream")
    # DEFAULT is (600/min, capacity=120)
    st = b.status()
    assert st["capacity"] == 120
    assert st["tokens_per_min"] == 600


def test_webhook_per_host():
    a = ratelimit.webhook_bucket_for("https://a.example.com/hook")
    b = ratelimit.webhook_bucket_for("https://b.example.com/hook")
    assert a is not b
    assert a.name == "webhook.a.example.com"
    assert b.name == "webhook.b.example.com"


def test_acquire_n_tokens_at_once():
    b = ratelimit.TokenBucket("t", tokens_per_min=60, capacity=10)
    assert b.acquire(5)
    assert b.acquire(5)
    assert not b.acquire(1)

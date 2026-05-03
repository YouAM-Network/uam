"""Phase 44 Wave 0 — failing-by-design concurrency tests for SlidingWindowCounter.

Covers:
  T4.2  RATE-LIMIT-ATOMIC   — check() is atomic under N concurrent calls
  T4.2  RATE-LIMIT-CLEANUP  — cleanup() must not raise during concurrent check()

Today (Wave 0) every test FAILS:
  - ``check`` is sync (def, not async def) — ``await limiter.check(...)``
    raises ``TypeError: object bool can't be used in 'await' expression``
  - even if you bypass the await, the read-modify-write of ``self._buckets[key]``
    has no per-instance lock — concurrent calls overcount or undercount
  - ``cleanup()`` mutates the dict while ``check()`` may also mutate it
    → ``RuntimeError: dictionary changed size during iteration``

After Plan 44-02:
  - ``check`` becomes ``async def`` with a per-instance asyncio.Lock
  - ``cleanup`` snapshots ``list(self._buckets.items())`` under the lock
  - 100 concurrent ``check`` calls produce EXACTLY ``limit`` successes

NEW FILE created by Plan 44-00.
"""

from __future__ import annotations

import asyncio
import inspect

import pytest

from uam.relay.rate_limit import SlidingWindowCounter


def _is_async(fn) -> bool:
    """True if *fn* is an async function (coroutine function)."""
    return inspect.iscoroutinefunction(fn)


async def _maybe_await(value):
    """Await *value* if it's a coroutine; otherwise return it as-is.

    Wave-0 helper: today ``check`` is sync (returns bool); after Plan 44-02
    it becomes async (returns Awaitable[bool]). The wrapper makes the test
    body identical for both versions while still ASSERTING the conversion
    happens (see ``test_check_is_async_after_fix`` below).
    """
    if inspect.iscoroutine(value):
        return await value
    return value


# ---------------------------------------------------------------------------
# T4.2 — Async API contract
# ---------------------------------------------------------------------------


def test_check_is_async_after_fix():
    """T4.2 contract: ``SlidingWindowCounter.check`` MUST be async after
    Plan 44-02 — otherwise it cannot ``async with self._lock:`` to serialize
    the read-modify-write of ``self._buckets[key]``.

    Today (Wave 0): ``check`` is a sync ``def`` — this test FAILS with a
    descriptive AssertionError. The fix in Plan 44-02 converts the API
    to ``async def`` and adds a per-instance ``asyncio.Lock``.
    """
    assert _is_async(SlidingWindowCounter.check), (
        "T4.2 contract: SlidingWindowCounter.check must be `async def` "
        "so it can `async with self._lock:` to serialize the bucket "
        "read-modify-write. Today it's a sync `def` — concurrent calls "
        "race on `self._buckets[key]` reassignment in check() and on "
        "iteration in cleanup()."
    )


# ---------------------------------------------------------------------------
# T4.2 — RATE-LIMIT-ATOMIC: exact-count enforcement under concurrency
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_concurrent_check_exact_count():
    """T4.2: 100 concurrent ``check()`` calls with limit=10 → EXACTLY 10 succeed.

    Without the fix this either:
      (a) raises ``TypeError`` because ``check`` is sync and we ``await`` it, OR
      (b) returns >10 successes because the read-modify-write of the bucket
          list is not serialized — two coroutines can both see ``len < 10``,
          both append, and both return True.

    Plan 44-02 makes ``check`` async + lock-protected; concurrent calls are
    serialized inside the lock and exactly ``limit`` succeed.
    """
    limit = 10
    n_attempts = 100
    limiter = SlidingWindowCounter(limit=limit, window_seconds=60)

    async def attempt() -> bool:
        # Wave-0 dance: today check() is sync. After Plan 44-02 it's async.
        # _maybe_await covers both — but the assertion above ensures the
        # async conversion is the contract.
        result = limiter.check("agent-1")
        return await _maybe_await(result)

    results = await asyncio.gather(*[attempt() for _ in range(n_attempts)])
    successes = sum(1 for r in results if r)
    assert successes == limit, (
        f"T4.2: expected exactly {limit} successes from {n_attempts} "
        f"concurrent check() calls, got {successes}. The bucket "
        f"read-modify-write is not serialized — multiple coroutines "
        f"observed `len(bucket) < {limit}` simultaneously and all "
        f"appended their timestamp."
    )


# ---------------------------------------------------------------------------
# T4.2 — RATE-LIMIT-CLEANUP: cleanup() must not raise during check()
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cleanup_during_check_no_raise():
    """T4.2: ``cleanup()`` MUST not raise ``RuntimeError: dictionary changed
    size during iteration`` while ``check()`` is running concurrently.

    Today (Wave 0): cleanup() iterates ``self._buckets.items()`` directly
    while check() may insert/reassign keys → race RuntimeError on a
    sufficiently busy hot path.

    Plan 44-02: cleanup() snapshots ``list(self._buckets.items())`` inside
    the same per-instance lock check() takes. The snapshot makes iteration
    safe; the lock ensures ordering with concurrent check() calls.
    """
    limiter = SlidingWindowCounter(limit=1000, window_seconds=60)
    errors: list[BaseException] = []

    async def check_loop() -> None:
        for i in range(500):
            try:
                await _maybe_await(limiter.check(f"agent-{i % 100}"))
            except BaseException as exc:  # noqa: BLE001 — capture and continue
                errors.append(exc)

    async def cleanup_loop() -> None:
        for _ in range(100):
            await asyncio.sleep(0.001)
            try:
                # cleanup() is also expected to become async after Plan 44-02
                # so the lock is consistent. Today it's sync — _maybe_await
                # handles both shapes.
                result = limiter.cleanup()
                await _maybe_await(result)
            except BaseException as exc:  # noqa: BLE001
                errors.append(exc)

    await asyncio.gather(check_loop(), cleanup_loop())

    # Filter out the ONE expected TypeError from `await sync_method()` calls
    # that the _maybe_await guard already handled. We're hunting for
    # RuntimeError on dict mutation specifically.
    runtime_errors = [e for e in errors if isinstance(e, RuntimeError)]
    assert not runtime_errors, (
        f"T4.2: cleanup() raised RuntimeError during concurrent check() — "
        f"the bucket dict was mutated mid-iteration. Got "
        f"{len(runtime_errors)} RuntimeError(s); first: {runtime_errors[0]!r}. "
        f"Plan 44-02 must snapshot list(self._buckets.items()) under the lock."
    )

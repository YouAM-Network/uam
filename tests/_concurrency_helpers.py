"""Concurrency test helpers: sleep injection for race-window control.

Per Phase 44 RESEARCH § Pitfall 4 (MEDIUM-confidence note): adversarial
concurrency tests can be flaky on fast machines because the race window
between SELECT and UPDATE (or between two state-mutation steps) never
opens — the Python event loop happens to serialize the coroutines before
any actual roundtrip. A bug-and-fix can both pass the test on a fast
machine.

These helpers monkeypatch a target callable to ``await asyncio.sleep(N)``
at a specific point, GUARANTEEING the race window opens regardless of
machine speed. Buggy code reliably exhibits the race; correct code
(atomic SQL UPDATE or asyncio.Lock) reliably wins exactly-once.

Usage:

    async def test_concurrent_claim_one_winner(monkeypatch, session_factory):
        # Force a 10ms gap between SELECT and UPDATE inside claim_reservation
        from tests._concurrency_helpers import inject_sleep_after
        inject_sleep_after(
            monkeypatch,
            "uam.db.crud.reservations.get_reservation_by_token",
            sleep_ms=10,
        )
        # Now any race window in claim_reservation is FORCED open;
        # the buggy code WILL exhibit double-claim, the atomic-UPDATE fix
        # WILL still produce exactly 1 winner.
        ...

Both helpers are no-ops in production code paths — they only attach to
the SUT during the lifetime of a single test via monkeypatch.

Wave 0 contract:
    - inject_sleep_after  — wrap target so it sleeps AFTER returning
    - inject_sleep_before — wrap target so it sleeps BEFORE calling original
"""

from __future__ import annotations

import asyncio
import importlib
from typing import Any


def inject_sleep_after(
    monkeypatch, dotted_target: str, *, sleep_ms: int = 10
) -> None:
    """Wrap *dotted_target* so it awaits ``asyncio.sleep(sleep_ms/1000)`` AFTER returning.

    Use to force a race window between a SELECT-style call and the next
    mutation. The target must be an awaitable function (the wrapper preserves
    async signature).

    Parameters
    ----------
    monkeypatch:
        The pytest ``monkeypatch`` fixture.
    dotted_target:
        Dotted path to the callable to wrap, e.g.
        ``"uam.db.crud.reservations.get_reservation_by_token"``.
    sleep_ms:
        Milliseconds to await.sleep AFTER the wrapped function returns.
        Default 10ms — enough to deterministically open the race window
        on every machine we've tested.
    """
    module_path, _, attr = dotted_target.rpartition(".")
    module = importlib.import_module(module_path)
    original = getattr(module, attr)

    async def wrapper(*args: Any, **kwargs: Any):
        result = await original(*args, **kwargs)
        await asyncio.sleep(sleep_ms / 1000.0)
        return result

    monkeypatch.setattr(module, attr, wrapper)


def inject_sleep_before(
    monkeypatch, dotted_target: str, *, sleep_ms: int = 10
) -> None:
    """Wrap *dotted_target* so it awaits ``asyncio.sleep(sleep_ms/1000)`` BEFORE calling original.

    Mirror of :func:`inject_sleep_after` for cases where the race window
    needs to open on the entry side of a function rather than the exit
    side. Wave 0 only uses ``inject_sleep_after``; this helper is provided
    for completeness so future plans (44-01..44-08) don't need to add a
    second helper.

    Parameters
    ----------
    monkeypatch:
        The pytest ``monkeypatch`` fixture.
    dotted_target:
        Dotted path to the callable to wrap.
    sleep_ms:
        Milliseconds to await.sleep BEFORE calling the wrapped function.
    """
    module_path, _, attr = dotted_target.rpartition(".")
    module = importlib.import_module(module_path)
    original = getattr(module, attr)

    async def wrapper(*args: Any, **kwargs: Any):
        await asyncio.sleep(sleep_ms / 1000.0)
        return await original(*args, **kwargs)

    monkeypatch.setattr(module, attr, wrapper)

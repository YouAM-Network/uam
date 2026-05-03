"""Phase 44 Wave 0 — failing-by-design concurrency tests for ConnectionManager.

Covers:
  T4.1  WS-FRAME-INTERLEAVE          — per-connection send lock
  T4.1  M8 (drain via send_to)       — _deliver_stored_messages routes through manager
  T4.3  REGISTRY-LOCK-RELEASE        — connect() must release lock before await ws.close()

Today (Wave 0) every test FAILS or RAISES — the failure mode is the
contract that Plans 44-01 / 44-02 must satisfy.

NEW FILE created by Plan 44-00.
"""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path

import pytest
from starlette.websockets import WebSocket


# ---------------------------------------------------------------------------
# T4.1 — WS-FRAME-INTERLEAVE: per-connection send lock
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_concurrent_sends_do_not_interleave_frames(client, registered_agent):
    """T4.1: 50 concurrent send_to calls to one address; every received frame
    is standalone JSON (no interleaved bytes mid-message).

    Plan 44-01 contract:
      - ``LockedWebSocket`` wraps the raw Starlette WebSocket
      - ``LockedWebSocket.send_json`` acquires a per-connection asyncio.Lock
      - ``ConnectionManager.send_to`` funnels through that lock
      - 50 concurrent send_to calls produce 50 well-formed JSON frames

    Today (Wave 0): ``ConnectionManager.send_to`` calls ``ws.send_json``
    directly without per-connection serialization. ``WebSocket.send_json``
    is implemented as multiple ASGI events and CAN interleave under
    ``asyncio.gather`` — this test FAILS with one of:
      - ``json.JSONDecodeError`` on a corrupted frame
      - ``RuntimeError: Unexpected ASGI message 'websocket.send'``
      - missing ``seq`` values (some frames clobbered)
    """
    address = registered_agent["address"]
    token = registered_agent["token"]
    n_sends = 50
    payloads = [{"seq": i, "msg": "x" * 256} for i in range(n_sends)]

    with client.websocket_connect(
        "/ws", subprotocols=[f"bearer.{token}"]
    ) as ws:
        manager = client.app.state.manager

        # Hammer the single connection with N concurrent server-side sends.
        await asyncio.gather(*[manager.send_to(address, p) for p in payloads])

        seen_seqs: set[int] = set()
        for _ in range(n_sends):
            raw = ws.receive_text()
            data = json.loads(raw)  # raises if interleaved
            assert "seq" in data, f"Missing 'seq' field — frame likely interleaved: {raw!r}"
            seen_seqs.add(data["seq"])

        assert seen_seqs == set(range(n_sends)), (
            f"T4.1: expected seqs 0..{n_sends - 1}, got {sorted(seen_seqs)}. "
            f"Missing: {set(range(n_sends)) - seen_seqs}. This indicates "
            f"frame interleave OR lost frames — both fixed by LockedWebSocket."
        )


# ---------------------------------------------------------------------------
# T4.1 M8 — _deliver_stored_messages must route through manager.send_to
# ---------------------------------------------------------------------------


def test_deliver_stored_messages_routes_through_send_to():
    """T4.1 M8: ``_deliver_stored_messages`` MUST funnel through
    ``manager.send_to`` (not call ``websocket.send_json`` directly).

    After Plan 44-01 the drain path shares the per-connection
    LockedWebSocket lock with every other send path. Today the drain
    bypasses the manager and writes ``await websocket.send_json`` directly
    on the raw socket — this is the M8 finding from REVIEW-relay-core.

    This is a SOURCE-GREP test: it reads ws.py and asserts the dangerous
    line is gone from the ``_deliver_stored_messages`` body. Source-grep
    tests are durable across refactors as long as the function name
    survives.
    """
    src_path = Path(__file__).resolve().parents[2] / "src" / "uam" / "relay" / "ws.py"
    src = src_path.read_text()

    assert "def _deliver_stored_messages" in src, (
        f"Could not locate _deliver_stored_messages in {src_path}. "
        f"Test needs updating if the function was renamed."
    )

    # Slice out the function body (from its def to the next top-level def or async def).
    body = src.split("def _deliver_stored_messages", 1)[1]
    body = body.split("\nasync def ", 1)[0].split("\ndef ", 1)[0]

    forbidden = "await websocket.send_json(envelope_data)"
    assert forbidden not in body, (
        "T4.1 M8 not closed: _deliver_stored_messages still calls "
        f"`{forbidden}` directly on the raw WebSocket — this bypasses the "
        "per-connection LockedWebSocket lock and races with concurrent "
        "sends from the recv loop / heartbeat / peer forwarding. Plan 44-01 "
        "must route the drain through manager.send_to(address, envelope_data)."
    )


# ---------------------------------------------------------------------------
# T4.3 — REGISTRY-LOCK-RELEASE: don't hold registry lock across await ws.close()
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_connect_does_not_block_registry_during_close(monkeypatch):
    """T4.3: ``ConnectionManager.connect()`` must release the registry lock
    BEFORE awaiting ``old.close()`` so a single half-dead client cannot
    wedge every other registry operation behind a slow TCP close.

    Plan 44-02 contract (per RESEARCH Pattern 2):
      - capture ``old`` while holding lock, swap in new socket, release
        lock, THEN ``await old.close()`` outside the lock
      - concurrent ``send_to`` / ``disconnect`` / ``connect`` for OTHER
        addresses complete in <100ms even if the old socket's close()
        sleeps for seconds

    Today (Wave 0): ``connect()`` does ``async with self._lock: ...
    await old.close()`` — the lock is held across the close. A slow close
    blocks every other registry op, including disconnects of completely
    unrelated addresses. This test FAILS today because the disconnect
    of "other-address" gets stuck behind the slow-closing connection.
    """
    from uam.relay.connections import ConnectionManager

    manager = ConnectionManager()

    close_started = asyncio.Event()
    close_can_finish = asyncio.Event()

    class SlowClosingWebSocket:
        """A fake WS whose close() awaits forever until released."""

        async def close(self, code: int = 1000, reason: str = "") -> None:
            close_started.set()
            await close_can_finish.wait()  # blocks until the test releases

        async def send_json(self, data) -> None:
            pass

    class FastWebSocket:
        """A fake WS with no-op operations (close + send return immediately)."""

        async def close(self, code: int = 1000, reason: str = "") -> None:
            return None

        async def send_json(self, data) -> None:
            pass

    # Step 1: register the slow-closing connection on "alice"
    slow_ws = SlowClosingWebSocket()
    await manager.connect("alice::test.local", slow_ws)  # type: ignore[arg-type]

    # Step 2: register a different fast-closing connection on "bob"
    bob_ws = FastWebSocket()
    await manager.connect("bob::test.local", bob_ws)  # type: ignore[arg-type]

    # Step 3: replace alice with a new connection — this triggers
    # `await old.close()` on the slow socket. Run it as a background task.
    new_alice_ws = FastWebSocket()
    replace_task = asyncio.create_task(
        manager.connect("alice::test.local", new_alice_ws)  # type: ignore[arg-type]
    )

    # Wait until close() has started on the slow socket — proves connect()
    # has reached the await old.close() step.
    try:
        await asyncio.wait_for(close_started.wait(), timeout=2.0)
    except asyncio.TimeoutError:
        close_can_finish.set()
        replace_task.cancel()
        pytest.fail(
            "T4.3 setup failure: replace task did not call old.close() within 2s"
        )

    # Step 4: while close() is parked, time how long an UNRELATED disconnect
    # takes. With the bug (lock held during close), this disconnect blocks
    # behind the slow close. With the fix, it completes immediately.
    start = time.monotonic()
    try:
        await asyncio.wait_for(manager.disconnect("bob::test.local"), timeout=0.5)
        elapsed = time.monotonic() - start
    except asyncio.TimeoutError:
        elapsed = time.monotonic() - start
        # Release the slow close so the test framework can clean up.
        close_can_finish.set()
        await asyncio.wait_for(replace_task, timeout=2.0)
        pytest.fail(
            f"T4.3: unrelated disconnect('bob') blocked for >500ms "
            f"({elapsed:.3f}s) while alice's old connection was closing. "
            f"This proves the registry lock is held across await old.close(). "
            f"Plan 44-02 must capture old INSIDE the lock, release the lock, "
            f"then await old.close() OUTSIDE the lock."
        )

    # Release the slow close and wait for replace_task to finish.
    close_can_finish.set()
    await asyncio.wait_for(replace_task, timeout=2.0)

    # The disconnect must have been near-instantaneous (well under 100ms).
    assert elapsed < 0.1, (
        f"T4.3: unrelated disconnect('bob') took {elapsed * 1000:.1f}ms "
        f"while alice's slow close was in flight. Expected <100ms. "
        f"The registry lock is being held across await old.close()."
    )


# Module sanity import — keeps `pytest --collect-only` honest if Starlette
# WebSocket symbol changes shape across versions.
_ = WebSocket

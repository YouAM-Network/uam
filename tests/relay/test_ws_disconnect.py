"""What the relay does when a WebSocket ends, however it ends.

The handler can be cancelled rather than told about a disconnect.  Its
cleanup must still finish: a database call cancelled half way makes
SQLAlchemy terminate the connection, and with aiosqlite 0.22 that can leave
close() waiting on a worker thread that has already exited, which hangs
shutdown.
"""

from __future__ import annotations

import asyncio
import time
from unittest.mock import patch

import aiosqlite

import uam.relay.ws as ws_module


def _wait_until(condition, timeout: float = 2.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(0.01)
    return condition()


def test_last_seen_update_survives_the_handler_being_cancelled(
    client, app, registered_agent
):
    finished = []
    real_update = ws_module.update_agent

    async def slow_update(session, address, **fields):
        await asyncio.sleep(0.1)  # long enough for the cancel to land
        result = await real_update(session, address, **fields)
        finished.append(address)
        return result

    with patch.object(ws_module, "update_agent", slow_update):
        with client.websocket_connect(
            "/ws", headers={"Authorization": f"Bearer {registered_agent['token']}"}
        ):
            pass
        assert _wait_until(lambda: finished), "last_seen update was cancelled"


def test_connection_is_forgotten_when_the_handler_is_cancelled(
    client, app, registered_agent
):
    address = registered_agent["address"]
    manager = app.state.manager

    async def slow_update(session, address, **fields):
        await asyncio.sleep(0.1)

    with patch.object(ws_module, "update_agent", slow_update):
        with client.websocket_connect(
            "/ws", headers={"Authorization": f"Bearer {registered_agent['token']}"}
        ):
            assert manager.is_online(address)
        assert _wait_until(lambda: not manager.is_online(address))


async def test_aiosqlite_close_returns_after_a_forced_stop(tmp_path):
    """What SQLAlchemy does to a connection whose query was cancelled.

    Guards the shim in tests/conftest.py; drop both once aiosqlite fixes this.
    """
    conn = await aiosqlite.connect(tmp_path / "x.db")
    closing = asyncio.create_task(conn.close())
    await asyncio.sleep(0)
    conn.stop()
    await asyncio.wait_for(closing, timeout=2)


def test_unsupported_version_gets_an_error_and_keeps_the_connection(
    client, registered_agent_pair, make_envelope
):
    alice, bob = registered_agent_pair
    bad = make_envelope(alice, bob)
    bad["uam_version"] = "9.0"

    with client.websocket_connect(
        "/ws", headers={"Authorization": f"Bearer {alice['token']}"}
    ) as ws:
        ws.send_json(bad)
        frame = ws.receive_json()
        assert frame["error"] == "invalid_envelope"
        assert "9.0" in frame["detail"]

        ws.send_json(make_envelope(alice, bob))
        assert ws.receive_json()["type"] == "ack"

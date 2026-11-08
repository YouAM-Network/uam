"""A stalled recipient socket can't hold up delivery.

The live send runs inside the sender's open transaction, so a socket that
stops reading must not keep it open.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock

import pytest

from uam.relay.connections import ConnectionManager


class StalledSocket:
    def __init__(self) -> None:
        self.close = AsyncMock()

    async def send_json(self, data) -> None:
        await asyncio.Event().wait()


@pytest.fixture(autouse=True)
def _short_timeout(monkeypatch):
    monkeypatch.setattr("uam.relay.connections.SEND_TIMEOUT_SECONDS", 0.05)


async def test_a_stalled_send_gives_up_and_drops_the_connection():
    manager = ConnectionManager()
    socket = StalledSocket()
    manager._connections["bob::test.local"] = socket

    delivered = await asyncio.wait_for(manager.send_to("bob::test.local", {}), timeout=2)

    assert delivered is False
    assert not manager.is_online("bob::test.local")


async def test_a_stalled_socket_is_closed_so_the_client_reconnects():
    manager = ConnectionManager()
    socket = StalledSocket()
    manager._connections["bob::test.local"] = socket

    await manager.send_to("bob::test.local", {})
    await asyncio.gather(*manager._closing)

    socket.close.assert_awaited_once()


async def test_a_socket_that_will_not_close_does_not_leak_a_task():
    manager = ConnectionManager()
    socket = StalledSocket()
    socket.close = lambda **kwargs: asyncio.Event().wait()
    manager._connections["bob::test.local"] = socket

    await manager.send_to("bob::test.local", {})
    await asyncio.wait_for(asyncio.gather(*manager._closing), timeout=2)
    await asyncio.sleep(0)

    assert not manager._closing


def test_a_message_to_a_stalled_recipient_is_stored(
    client, app, registered_agent_pair, make_envelope
):
    alice, bob = registered_agent_pair
    app.state.manager._connections[bob["address"]] = StalledSocket()
    wire = make_envelope(alice, bob)

    resp = client.post(
        "/api/v1/send",
        json={"envelope": wire},
        headers={"Authorization": f"Bearer {alice['token']}"},
    )

    assert resp.status_code == 200, resp.text
    inbox = client.get(
        f"/api/v1/inbox/{bob['address']}",
        headers={"Authorization": f"Bearer {bob['token']}"},
    )
    assert [m["message_id"] for m in inbox.json()["messages"]] == [wire["message_id"]]

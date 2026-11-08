"""A WebSocket client answers for what it sent before it closes.

Once the relay can't write an ack to a closing socket, its server stops
reading: frames still in flight are lost, however soon after send() the agent
closes.  So disconnect() waits for the relay's answers.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from uam.sdk.transport.websocket import WebSocketTransport


@pytest.fixture()
def transport():
    transport = WebSocketTransport("ws://relay.test/ws", "a-token")
    transport._ws = AsyncMock()
    return transport


async def _closing(transport) -> asyncio.Task:
    task = asyncio.create_task(transport.disconnect())
    await asyncio.sleep(0.01)
    return task


async def test_it_waits_for_every_ack_before_closing(transport):
    await transport.send({"message_id": "m1"})
    await transport.send({"message_id": "m2"})
    closing = await _closing(transport)

    await transport._handle_message({"type": "ack", "message_id": "m1"})
    await asyncio.sleep(0.01)
    transport._ws.close.assert_not_awaited()

    await transport._handle_message({"type": "ack", "message_id": "m2"})
    await closing
    transport._ws.close.assert_awaited_once()


async def test_an_error_frame_is_an_answer(transport):
    await transport.send({"message_id": "m1"})
    closing = await _closing(transport)

    await transport._handle_message({"error": "rate_limited", "detail": "slow down"})

    await closing
    transport._ws.close.assert_awaited_once()


async def test_a_relay_that_never_answers_can_t_hold_the_close_open(transport):
    await transport.send({"message_id": "m1"})
    with patch("uam.sdk.transport.websocket.SEND_SETTLE_SECONDS", 0.01):
        await transport.disconnect()
    transport._ws.close.assert_awaited_once()


async def test_nothing_sent_means_no_wait(transport):
    await asyncio.wait_for(transport.disconnect(), timeout=0.5)
    transport._ws.close.assert_awaited_once()


async def test_an_ack_that_arrives_during_the_send_still_counts(transport):
    async def ack_arrives(_frame):
        await transport._handle_message({"type": "ack", "message_id": "m1"})

    transport._ws.send.side_effect = ack_arrives
    await transport.send({"message_id": "m1"})

    await asyncio.wait_for(transport.disconnect(), timeout=0.5)


async def test_a_send_that_fails_is_not_waited_for(transport):
    transport._ws.send.side_effect = OSError("gone")
    with pytest.raises(OSError):
        await transport.send({"message_id": "m1"})

    await asyncio.wait_for(transport.disconnect(), timeout=0.5)


@pytest.mark.parametrize("frame", [
    {"uam_version": "0.1", "type": "ack", "message_id": "m9"},
    {"uam_version": "0.1", "type": "message", "error": "x", "message_id": "m9"},
])
async def test_an_envelope_is_never_read_as_the_relay_s_answer(transport, frame):
    await transport.send({"message_id": "m1"})

    await transport._handle_message(frame)

    assert transport._unanswered == 1
    assert await transport.receive() == [frame]

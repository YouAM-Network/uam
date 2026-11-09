"""A WebSocket client answers for what it sent before it closes.

Once the relay can't write an ack to a closing socket, its server stops
reading: frames still in flight are lost, however soon after send() the agent
closes.  So disconnect() waits for the relay's answers.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from uam.protocol.errors import SendRefusedError
from uam.sdk.transport.websocket import WebSocketTransport


@pytest.fixture()
def transport(monkeypatch):
    # These tests answer after send() returns: don't let send() wait for it.
    monkeypatch.setattr("uam.sdk.transport.websocket.ACK_TIMEOUT_SECONDS", 0.01)
    transport = WebSocketTransport("ws://relay.test/ws", "a-token")
    transport._ws = AsyncMock()
    return transport


@pytest.fixture()
def waiting_transport():
    """A transport whose send() waits for the relay's answer, as in use."""
    transport = WebSocketTransport("ws://relay.test/ws", "a-token")
    transport._ws = AsyncMock()
    return transport


async def _sending(transport, message_id="m1") -> asyncio.Task:
    task = asyncio.create_task(transport.send({"message_id": message_id}))
    await asyncio.sleep(0.01)
    return task


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


# -- send() returns the relay's answer (A2a) ----------------------------------


async def test_send_returns_the_ack_for_its_message(waiting_transport):
    sending = await _sending(waiting_transport)

    # Another message's ack is not this one's answer
    await waiting_transport._handle_message({"type": "ack", "message_id": "m0", "status": "stored"})
    assert not sending.done()

    ack = {"type": "ack", "message_id": "m1", "status": "stored", "delivered": False}
    await waiting_transport._handle_message(ack)
    assert await asyncio.wait_for(sending, 0.5) == ack


async def test_an_error_naming_the_message_refuses_the_send(waiting_transport):
    sending = await _sending(waiting_transport)

    await waiting_transport._handle_message(
        {"error": "rate_limited", "detail": "slow down", "message_id": "m1"}
    )

    with pytest.raises(SendRefusedError) as refused:
        await asyncio.wait_for(sending, 0.5)
    assert refused.value.code == "rate_limited"
    assert refused.value.message_id == "m1"


async def test_no_answer_in_time_is_none(waiting_transport, monkeypatch):
    monkeypatch.setattr("uam.sdk.transport.websocket.ACK_TIMEOUT_SECONDS", 0.05)
    # An old relay's error names no message: it can't settle the send
    sending = await _sending(waiting_transport)
    await waiting_transport._handle_message({"error": "rate_limited", "detail": "x"})

    assert await asyncio.wait_for(sending, 0.5) is None
    assert waiting_transport._waiting == {}


async def test_a_lost_socket_ends_the_wait(waiting_transport):
    sending = await _sending(waiting_transport)

    waiting_transport._abandon_waiting()

    assert await asyncio.wait_for(sending, 0.5) is None


async def test_a_send_from_the_reader_loop_does_not_wait(waiting_transport):
    """An on_message callback runs in the loop that reads answers: a send
    from it (a handshake accept) must not wait for an answer it blocks."""

    async def reader():
        return await waiting_transport.send({"message_id": "m1"})

    # Named as the reader before it first runs
    waiting_transport._listen_task = task = asyncio.create_task(reader())
    assert await asyncio.wait_for(task, 0.5) is None

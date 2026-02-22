"""Tests for SDK receipt.read generation and anti-loop guard (RCPT-01).

Verifies that agent.inbox() automatically sends receipt.read envelopes
for user messages, and that receipt/handshake/session messages are skipped.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import pytest

from uam.protocol import (
    MessageType,
    create_envelope,
    decrypt_payload,
    generate_keypair,
    serialize_verify_key,
    deserialize_verify_key,
    to_wire_dict,
    from_wire_dict,
    verify_envelope,
)
from uam.sdk.agent import Agent
from uam.sdk.message import ReceivedMessage


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _make_agent(tmp_path, name="bob"):
    """Create a minimal Agent with open contact book and mock transport."""
    agent = Agent(
        name,
        relay="http://testserver",
        key_dir=str(tmp_path / "keys"),
        auto_register=False,
        transport="http",
    )
    agent._key_manager.load_or_generate(name)
    agent._address = f"{name}::test.local"
    agent._connected = True

    # Open contact book
    await agent._contact_book.open()

    # Mock transport
    agent._transport = AsyncMock()
    agent._transport.send = AsyncMock()
    agent._transport.receive = AsyncMock(return_value=[])

    return agent


def _create_message_envelope(sender_sk, sender_vk, recipient_vk, msg_type=MessageType.MESSAGE):
    """Create a valid signed+encrypted envelope from sender to recipient."""
    plaintext = b"Hello, this is a test message!"
    envelope = create_envelope(
        from_address="alice::test.local",
        to_address="bob::test.local",
        message_type=msg_type,
        payload_plaintext=plaintext,
        signing_key=sender_sk,
        recipient_verify_key=recipient_vk,
    )
    return to_wire_dict(envelope), envelope.message_id


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestReceiptRead:
    """Tests for receipt.read auto-generation in inbox()."""

    async def test_inbox_sends_receipt_read(self, tmp_path):
        """Receiving a regular message triggers transport.send with receipt.read."""
        sk_a, vk_a = generate_keypair()
        agent = await _make_agent(tmp_path)

        # Add alice to contacts
        await agent._contact_book.add_contact(
            "alice::test.local", serialize_verify_key(vk_a)
        )

        # Create a valid message from alice
        wire, msg_id = _create_message_envelope(
            sk_a, vk_a, agent._key_manager.verify_key
        )
        agent._transport.receive = AsyncMock(return_value=[wire])

        # Call inbox
        messages = await agent.inbox()

        # Should have received 1 message
        assert len(messages) == 1
        assert messages[0].message_id == msg_id

        # Transport.send should have been called (receipt.read)
        assert agent._transport.send.call_count == 1

        # Parse the sent envelope to verify it's a receipt.read
        sent_wire = agent._transport.send.call_args[0][0]
        sent_envelope = from_wire_dict(sent_wire)
        assert sent_envelope.type == MessageType.RECEIPT_READ.value
        assert sent_envelope.from_address == "bob::test.local"
        assert sent_envelope.to_address == "alice::test.local"

        await agent._contact_book.close()

    async def test_receipt_read_is_signed_envelope(self, tmp_path):
        """The sent receipt.read is a full signed+encrypted UAM envelope."""
        sk_a, vk_a = generate_keypair()
        agent = await _make_agent(tmp_path)

        await agent._contact_book.add_contact(
            "alice::test.local", serialize_verify_key(vk_a)
        )

        wire, _ = _create_message_envelope(
            sk_a, vk_a, agent._key_manager.verify_key
        )
        agent._transport.receive = AsyncMock(return_value=[wire])

        await agent.inbox()

        # Verify the receipt envelope has all required fields
        sent_wire = agent._transport.send.call_args[0][0]
        sent_envelope = from_wire_dict(sent_wire)

        # Has required UAM envelope fields
        assert sent_envelope.message_id  # Non-empty
        assert sent_envelope.from_address == "bob::test.local"
        assert sent_envelope.to_address == "alice::test.local"
        assert sent_envelope.type == MessageType.RECEIPT_READ.value
        assert sent_envelope.signature  # Signed
        assert sent_envelope.payload  # Encrypted payload present
        assert sent_envelope.timestamp  # Timestamp present

        # Verify the signature is valid (using bob's verify key)
        verify_envelope(sent_envelope, agent._key_manager.verify_key)

        await agent._contact_book.close()

    async def test_no_receipt_for_receipt_delivered(self, tmp_path):
        """receipt.delivered messages do NOT trigger receipt.read (anti-loop)."""
        sk_a, vk_a = generate_keypair()
        agent = await _make_agent(tmp_path)

        await agent._contact_book.add_contact(
            "alice::test.local", serialize_verify_key(vk_a)
        )

        wire, _ = _create_message_envelope(
            sk_a, vk_a, agent._key_manager.verify_key,
            msg_type=MessageType.RECEIPT_DELIVERED,
        )
        agent._transport.receive = AsyncMock(return_value=[wire])

        messages = await agent.inbox()
        assert len(messages) == 1
        assert messages[0].type == MessageType.RECEIPT_DELIVERED.value

        # No receipt.read should be sent
        agent._transport.send.assert_not_called()

        await agent._contact_book.close()

    async def test_no_receipt_for_receipt_read(self, tmp_path):
        """receipt.read messages do NOT trigger further receipt.read (anti-loop)."""
        sk_a, vk_a = generate_keypair()
        agent = await _make_agent(tmp_path)

        await agent._contact_book.add_contact(
            "alice::test.local", serialize_verify_key(vk_a)
        )

        wire, _ = _create_message_envelope(
            sk_a, vk_a, agent._key_manager.verify_key,
            msg_type=MessageType.RECEIPT_READ,
        )
        agent._transport.receive = AsyncMock(return_value=[wire])

        messages = await agent.inbox()
        assert len(messages) == 1

        # No further receipt should be sent
        agent._transport.send.assert_not_called()

        await agent._contact_book.close()

    async def test_no_receipt_for_receipt_failed(self, tmp_path):
        """receipt.failed messages do NOT trigger receipt.read (anti-loop)."""
        sk_a, vk_a = generate_keypair()
        agent = await _make_agent(tmp_path)

        await agent._contact_book.add_contact(
            "alice::test.local", serialize_verify_key(vk_a)
        )

        wire, _ = _create_message_envelope(
            sk_a, vk_a, agent._key_manager.verify_key,
            msg_type=MessageType.RECEIPT_FAILED,
        )
        agent._transport.receive = AsyncMock(return_value=[wire])

        messages = await agent.inbox()
        assert len(messages) == 1

        # No receipt should be sent
        agent._transport.send.assert_not_called()

        await agent._contact_book.close()

    async def test_receipt_failure_does_not_break_inbox(self, tmp_path):
        """If transport.send raises during receipt, inbox still returns messages."""
        sk_a, vk_a = generate_keypair()
        agent = await _make_agent(tmp_path)

        await agent._contact_book.add_contact(
            "alice::test.local", serialize_verify_key(vk_a)
        )

        wire, msg_id = _create_message_envelope(
            sk_a, vk_a, agent._key_manager.verify_key
        )
        agent._transport.receive = AsyncMock(return_value=[wire])

        # Make transport.send raise an exception
        agent._transport.send = AsyncMock(side_effect=ConnectionError("network down"))

        # inbox() should still succeed and return the message
        messages = await agent.inbox()
        assert len(messages) == 1
        assert messages[0].message_id == msg_id
        assert messages[0].content == "Hello, this is a test message!"

        await agent._contact_book.close()

    async def test_receipt_read_payload_contains_message_id(self, tmp_path):
        """The receipt.read payload contains the original message_id."""
        sk_a, vk_a = generate_keypair()
        agent = await _make_agent(tmp_path)

        await agent._contact_book.add_contact(
            "alice::test.local", serialize_verify_key(vk_a)
        )

        wire, original_msg_id = _create_message_envelope(
            sk_a, vk_a, agent._key_manager.verify_key
        )
        agent._transport.receive = AsyncMock(return_value=[wire])

        await agent.inbox()

        # Decrypt the receipt payload
        sent_wire = agent._transport.send.call_args[0][0]
        sent_envelope = from_wire_dict(sent_wire)

        # Decrypt using alice's signing key + bob's verify key
        plaintext = decrypt_payload(
            sent_envelope.payload,
            sk_a,
            agent._key_manager.verify_key,
        )
        payload = json.loads(plaintext)
        assert payload["message_id"] == original_msg_id

        await agent._contact_book.close()

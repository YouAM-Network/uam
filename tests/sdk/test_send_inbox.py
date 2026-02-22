"""End-to-end encrypted send/inbox tests (SDK-02, SDK-03, SEC-03, SEC-04).

Tests verify encryption round-trip, signature verification, relay opacity,
and the full send/inbox pipeline at both unit and integration levels.
"""

from __future__ import annotations

import json

import pytest

from uam.protocol import (
    MessageType,
    create_envelope,
    verify_envelope,
    encrypt_payload,
    decrypt_payload,
    generate_keypair,
    serialize_verify_key,
    deserialize_verify_key,
    to_wire_dict,
    from_wire_dict,
    SignatureVerificationError,
    DecryptionError,
)
from uam.sdk.agent import Agent
from uam.sdk.contact_book import ContactBook
from uam.sdk.handshake import HandshakeManager
from uam.sdk.key_manager import KeyManager
from uam.sdk.message import ReceivedMessage


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _register_agent(client, name: str) -> dict:
    """Register an agent via the relay and return its details."""
    sk, vk = generate_keypair()
    pk_str = serialize_verify_key(vk)
    resp = client.post(
        "/api/v1/register",
        json={"agent_name": name, "public_key": pk_str},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    return {
        "address": data["address"],
        "token": data["token"],
        "signing_key": sk,
        "verify_key": vk,
        "public_key_str": pk_str,
    }


# ---------------------------------------------------------------------------
# Unit tests (no relay)
# ---------------------------------------------------------------------------

class TestEncryptDecryptRoundTrip:
    """Pure unit tests for encryption round-trip."""

    def test_encrypt_decrypt_round_trip(self):
        """Alice encrypts a message to Bob; Bob can decrypt it."""
        sk_a, vk_a = generate_keypair()
        sk_b, vk_b = generate_keypair()

        plaintext = b"Hello Bob, this is a secret!"
        envelope = create_envelope(
            from_address="alice::test.local",
            to_address="bob::test.local",
            message_type=MessageType.MESSAGE,
            payload_plaintext=plaintext,
            signing_key=sk_a,
            recipient_verify_key=vk_b,
        )

        # Wire format should NOT contain plaintext
        wire = to_wire_dict(envelope)
        assert "Hello Bob" not in str(wire)

        # Bob can verify and decrypt
        parsed = from_wire_dict(wire)
        verify_envelope(parsed, vk_a)
        decrypted = decrypt_payload(parsed.payload, sk_b, vk_a)
        assert decrypted == plaintext


class TestProcessInbound:
    """Tests for Agent._process_inbound() (the decryption/verification pipeline)."""

    async def _make_agent_with_contact_book(self, tmp_path, name="testbot"):
        """Create a minimal Agent-like setup for _process_inbound testing."""
        agent = Agent(
            name,
            relay="http://testserver",
            key_dir=str(tmp_path / "keys"),
            auto_register=False,
            transport="http",
        )
        agent._key_manager.load_or_generate(name)
        # Open contact book manually
        await agent._contact_book.open()
        return agent

    async def test_inbox_rejects_invalid_signature(self, tmp_path):
        """Messages with tampered signatures are silently rejected (SEC-03)."""
        sk_a, vk_a = generate_keypair()
        sk_b, vk_b = generate_keypair()

        agent = await self._make_agent_with_contact_book(tmp_path, "bob")

        # Pre-populate contact book with alice's key so agent can find it
        await agent._contact_book.add_contact(
            "alice::test.local", serialize_verify_key(vk_a)
        )

        # Create valid envelope, then tamper with signature
        envelope = create_envelope(
            from_address="alice::test.local",
            to_address="bob::test.local",
            message_type=MessageType.MESSAGE,
            payload_plaintext=b"legit message",
            signing_key=sk_a,
            recipient_verify_key=agent._key_manager.verify_key,
        )
        wire = to_wire_dict(envelope)
        wire["signature"] = "AAAA" + wire["signature"][4:]  # Tamper

        result = await agent._process_inbound(wire)
        assert result is None  # Rejected
        await agent._contact_book.close()

    async def test_inbox_rejects_decryption_failure(self, tmp_path):
        """Messages encrypted with wrong key are silently rejected."""
        sk_a, vk_a = generate_keypair()
        sk_wrong, vk_wrong = generate_keypair()

        agent = await self._make_agent_with_contact_book(tmp_path, "bob")

        # Pre-populate contact book with alice's key
        await agent._contact_book.add_contact(
            "alice::test.local", serialize_verify_key(vk_a)
        )

        # Encrypt to wrong recipient (vk_wrong instead of agent's key)
        envelope = create_envelope(
            from_address="alice::test.local",
            to_address="bob::test.local",
            message_type=MessageType.MESSAGE,
            payload_plaintext=b"message for someone else",
            signing_key=sk_a,
            recipient_verify_key=vk_wrong,  # Wrong recipient!
        )
        wire = to_wire_dict(envelope)

        result = await agent._process_inbound(wire)
        assert result is None  # Rejected due to decryption failure
        await agent._contact_book.close()

    async def test_process_inbound_returns_received_message(self, tmp_path):
        """Valid inbound messages produce ReceivedMessage objects."""
        sk_a, vk_a = generate_keypair()

        agent = await self._make_agent_with_contact_book(tmp_path, "bob")

        # Pre-populate contact book with alice's key
        await agent._contact_book.add_contact(
            "alice::test.local", serialize_verify_key(vk_a)
        )

        plaintext = "Hello Bob, secret message!"
        envelope = create_envelope(
            from_address="alice::test.local",
            to_address="bob::test.local",
            message_type=MessageType.MESSAGE,
            payload_plaintext=plaintext.encode("utf-8"),
            signing_key=sk_a,
            recipient_verify_key=agent._key_manager.verify_key,
        )
        wire = to_wire_dict(envelope)

        result = await agent._process_inbound(wire)
        assert result is not None
        assert isinstance(result, ReceivedMessage)
        assert result.content == plaintext
        assert result.from_address == "alice::test.local"
        assert result.verified is True
        await agent._contact_book.close()


# ---------------------------------------------------------------------------
# Integration tests (with relay)
# ---------------------------------------------------------------------------

class TestSendInboxViaRelay:
    """Integration tests using real relay endpoints."""

    def test_send_inbox_via_relay(self, relay_client):
        """Alice sends encrypted message via relay; Bob retrieves and decrypts."""
        alice = _register_agent(relay_client, "alice")
        bob = _register_agent(relay_client, "bob")

        plaintext = b"Secret message for Bob"
        envelope = create_envelope(
            from_address=alice["address"],
            to_address=bob["address"],
            message_type=MessageType.MESSAGE,
            payload_plaintext=plaintext,
            signing_key=alice["signing_key"],
            recipient_verify_key=bob["verify_key"],
        )
        wire = to_wire_dict(envelope)

        # Send via relay
        resp = relay_client.post(
            "/api/v1/send",
            json={"envelope": wire},
            headers={"Authorization": f"Bearer {alice['token']}"},
        )
        assert resp.status_code == 200

        # Bob retrieves inbox
        inbox_resp = relay_client.get(
            f"/api/v1/inbox/{bob['address']}",
            headers={"Authorization": f"Bearer {bob['token']}"},
        )
        assert inbox_resp.status_code == 200
        messages = inbox_resp.json()["messages"]
        assert len(messages) == 1

        # Verify and decrypt
        parsed = from_wire_dict(messages[0])
        verify_envelope(parsed, alice["verify_key"])
        decrypted = decrypt_payload(
            parsed.payload, bob["signing_key"], alice["verify_key"]
        )
        assert decrypted == plaintext

    def test_relay_cannot_read_content(self, relay_client):
        """SEC-04: The relay stores only ciphertext, never plaintext."""
        alice = _register_agent(relay_client, "alice")
        bob = _register_agent(relay_client, "bob")

        secret = b"TOP SECRET: nuclear launch codes"
        envelope = create_envelope(
            from_address=alice["address"],
            to_address=bob["address"],
            message_type=MessageType.MESSAGE,
            payload_plaintext=secret,
            signing_key=alice["signing_key"],
            recipient_verify_key=bob["verify_key"],
        )
        wire = to_wire_dict(envelope)

        relay_client.post(
            "/api/v1/send",
            json={"envelope": wire},
            headers={"Authorization": f"Bearer {alice['token']}"},
        )

        # Retrieve from relay -- payload must be encrypted
        inbox_resp = relay_client.get(
            f"/api/v1/inbox/{bob['address']}",
            headers={"Authorization": f"Bearer {bob['token']}"},
        )
        raw_envelope = inbox_resp.json()["messages"][0]
        payload_on_wire = raw_envelope["payload"]

        # Plaintext must not appear anywhere in the wire payload
        assert "TOP SECRET" not in payload_on_wire
        assert "nuclear" not in payload_on_wire
        assert "launch codes" not in str(raw_envelope)

    async def test_send_creates_contact_entry(self, tmp_path):
        """After resolving a recipient key, the contact book stores it."""
        sk_a, vk_a = generate_keypair()
        sk_b, vk_b = generate_keypair()

        book = ContactBook(tmp_path)
        await book.open()
        try:
            assert book.is_known("bob::test.local") is False

            # Simulate what Agent._resolve_public_key does
            await book.add_contact(
                "bob::test.local",
                serialize_verify_key(vk_b),
                trust_state="unverified",
            )
            assert book.is_known("bob::test.local") is True
        finally:
            await book.close()

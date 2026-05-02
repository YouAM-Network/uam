"""Tests for handshake flow (HAND-01 through HAND-04)."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from uam.protocol import (
    MessageType,
    create_envelope,
    create_contact_card,
    contact_card_to_dict,
    contact_card_from_dict,
    verify_contact_card,
    encrypt_payload_anonymous,
    decrypt_payload_anonymous,
    generate_keypair,
    serialize_verify_key,
    deserialize_verify_key,
    to_wire_dict,
    from_wire_dict,
)
from uam.sdk.contact_book import ContactBook
from uam.sdk.handshake import HandshakeManager


@pytest.fixture()
def data_dir(tmp_path):
    d = tmp_path / ".uam"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _mock_agent(sk, vk, address, relay_ws_url="ws://test/ws"):
    """Create a mock agent with the attributes HandshakeManager needs."""
    agent = MagicMock()
    agent.address = address
    agent._config = MagicMock()
    agent._config.display_name = address.split("::")[0]
    agent._config.relay_ws_url = relay_ws_url
    agent._key_manager = MagicMock()
    agent._key_manager.signing_key = sk
    agent._key_manager.verify_key = vk
    agent._transport = AsyncMock()
    return agent


def _make_handshake_request_envelope(sk_sender, vk_sender, sk_recipient, vk_recipient,
                                      sender_addr, recipient_addr):
    """Helper: create a handshake.request envelope from sender to recipient."""
    card = create_contact_card(
        address=sender_addr,
        display_name=sender_addr.split("::")[0],
        relay="ws://test/ws",
        signing_key=sk_sender,
    )
    card_json = json.dumps(contact_card_to_dict(card))
    envelope = create_envelope(
        from_address=sender_addr,
        to_address=recipient_addr,
        message_type=MessageType.HANDSHAKE_REQUEST,
        payload_plaintext=card_json.encode("utf-8"),
        signing_key=sk_sender,
        recipient_verify_key=vk_recipient,
    )
    return envelope, card


class TestHandshakeRequest:
    """HAND-01, HAND-02: Handshake request with contact card."""

    async def test_handshake_request_contains_contact_card(self, data_dir):
        """Handshake request payload is a valid, signed contact card."""
        sk_a, vk_a = generate_keypair()
        sk_b, vk_b = generate_keypair()

        book = ContactBook(data_dir)
        await book.open()
        try:
            manager = HandshakeManager(book, "auto-accept")
            agent = _mock_agent(sk_a, vk_a, "alice::test.local")

            wire = await manager.create_handshake_request(
                agent, "bob::test.local", vk_b
            )

            # The wire dict should be a valid envelope
            assert wire["type"] == MessageType.HANDSHAKE_REQUEST.value

            # Decrypt the payload (SealedBox -- recipient needs own signing key)
            plaintext = decrypt_payload_anonymous(wire["payload"], sk_b)
            card_dict = json.loads(plaintext.decode("utf-8"))

            # Verify card structure
            assert "address" in card_dict
            assert "public_key" in card_dict
            assert "signature" in card_dict
            assert card_dict["address"] == "alice::test.local"

            # Verify card signature
            card = contact_card_from_dict(card_dict)
            verify_contact_card(card)
        finally:
            await book.close()


class TestAutoAccept:
    """HAND-04: Auto-accept policy stores contact and sends accept."""

    async def test_auto_accept_stores_contact(self, data_dir):
        """Receiving a handshake.request with auto-accept stores the contact."""
        sk_a, vk_a = generate_keypair()
        sk_b, vk_b = generate_keypair()

        book = ContactBook(data_dir)
        await book.open()
        try:
            manager = HandshakeManager(book, "auto-accept")

            envelope, _ = _make_handshake_request_envelope(
                sk_a, vk_a, sk_b, vk_b, "alice::test.local", "bob::test.local"
            )

            # Create mock bob agent
            bob_agent = _mock_agent(sk_b, vk_b, "bob::test.local")

            # Handle the inbound handshake
            result = await manager.handle_inbound(bob_agent, envelope, vk_a)

            # Handshake messages return None (not user-visible)
            assert result is None

            # Contact should be stored
            assert book.is_known("alice::test.local") is True
            pk = await book.get_public_key("alice::test.local")
            assert pk == serialize_verify_key(vk_a)

            # Accept should have been sent back via transport
            bob_agent._transport.send.assert_called_once()
            sent_wire = bob_agent._transport.send.call_args[0][0]
            assert sent_wire["type"] == MessageType.HANDSHAKE_ACCEPT.value
        finally:
            await book.close()


class TestAutoAcceptTrustSource:
    """Auto-accept sets trust_source='auto-accepted' on the stored contact."""

    async def test_auto_accept_sets_trust_source(self, data_dir):
        """Verify trust_source is recorded as 'auto-accepted'."""
        sk_a, vk_a = generate_keypair()
        sk_b, vk_b = generate_keypair()

        book = ContactBook(data_dir)
        await book.open()
        try:
            manager = HandshakeManager(book, "auto-accept")

            envelope, _ = _make_handshake_request_envelope(
                sk_a, vk_a, sk_b, vk_b, "alice::test.local", "bob::test.local"
            )
            bob_agent = _mock_agent(sk_b, vk_b, "bob::test.local")
            await manager.handle_inbound(bob_agent, envelope, vk_a)

            # Verify trust_source via raw SQL
            async with book._db.execute(
                "SELECT trust_source FROM contacts WHERE address = ?",
                ("alice::test.local",),
            ) as cur:
                row = await cur.fetchone()
                assert row[0] == "auto-accepted-provisional"
        finally:
            await book.close()


class TestApprovalRequired:
    """Approval-required policy stores in pending, not contacts."""

    async def test_approval_required_stores_pending(self, data_dir):
        """With approval-required policy, contacts go to pending_handshakes."""
        sk_a, vk_a = generate_keypair()
        sk_b, vk_b = generate_keypair()

        book = ContactBook(data_dir)
        await book.open()
        try:
            manager = HandshakeManager(book, "approval-required")

            envelope, _ = _make_handshake_request_envelope(
                sk_a, vk_a, sk_b, vk_b, "alice::test.local", "bob::test.local"
            )

            bob_agent = _mock_agent(sk_b, vk_b, "bob::test.local")
            result = await manager.handle_inbound(bob_agent, envelope, vk_a)

            assert result is None
            # NOT in contacts
            assert book.is_known("alice::test.local") is False
            # IS in pending
            pending = await book.get_pending()
            assert len(pending) == 1
            assert pending[0]["address"] == "alice::test.local"
        finally:
            await book.close()


class TestAllowlistOnly:
    """HAND-01: allowlist-only policy auto-denies unknown senders."""

    async def test_allowlist_only_auto_denies_unknown(self, data_dir):
        """Handshake request from unknown sender is auto-denied with allowlist-only."""
        sk_a, vk_a = generate_keypair()
        sk_b, vk_b = generate_keypair()

        book = ContactBook(data_dir)
        await book.open()
        try:
            manager = HandshakeManager(book, "allowlist-only")

            envelope, _ = _make_handshake_request_envelope(
                sk_a, vk_a, sk_b, vk_b, "alice::test.local", "bob::test.local"
            )
            bob_agent = _mock_agent(sk_b, vk_b, "bob::test.local")
            result = await manager.handle_inbound(bob_agent, envelope, vk_a)

            assert result is None

            # NOT in contacts
            assert book.is_known("alice::test.local") is False

            # NOT in pending (allowlist-only does not store pending)
            pending = await book.get_pending()
            assert len(pending) == 0

            # handshake.deny should have been sent back
            bob_agent._transport.send.assert_called_once()
            sent_wire = bob_agent._transport.send.call_args[0][0]
            assert sent_wire["type"] == MessageType.HANDSHAKE_DENY.value
        finally:
            await book.close()

    async def test_allowlist_only_deny_payload_has_reason(self, data_dir):
        """The deny payload includes a reason field."""
        sk_a, vk_a = generate_keypair()
        sk_b, vk_b = generate_keypair()

        book = ContactBook(data_dir)
        await book.open()
        try:
            manager = HandshakeManager(book, "allowlist-only")

            envelope, _ = _make_handshake_request_envelope(
                sk_a, vk_a, sk_b, vk_b, "alice::test.local", "bob::test.local"
            )
            bob_agent = _mock_agent(sk_b, vk_b, "bob::test.local")
            await manager.handle_inbound(bob_agent, envelope, vk_a)

            # The sent deny envelope should exist
            sent_wire = bob_agent._transport.send.call_args[0][0]
            assert sent_wire["from"] == "bob::test.local"
            assert sent_wire["to"] == "alice::test.local"
        finally:
            await book.close()


class TestApproveFlow:
    """HAND-02: Approve a pending handshake request."""

    async def test_approve_stores_contact_with_trust_source(self, data_dir):
        """Approving a pending request stores contact with trust_source='explicit-approval'."""
        sk_a, vk_a = generate_keypair()
        sk_b, vk_b = generate_keypair()

        book = ContactBook(data_dir)
        await book.open()
        try:
            # Set up: store a pending handshake from alice
            manager = HandshakeManager(book, "approval-required")

            envelope, card = _make_handshake_request_envelope(
                sk_a, vk_a, sk_b, vk_b, "alice::test.local", "bob::test.local"
            )
            bob_agent = _mock_agent(sk_b, vk_b, "bob::test.local")
            await manager.handle_inbound(bob_agent, envelope, vk_a)

            # Verify alice is in pending
            pending = await book.get_pending()
            assert len(pending) == 1

            # Now simulate approve: parse the stored card, add contact, remove pending
            entry = pending[0]
            card_dict = json.loads(entry["contact_card"])
            parsed_card = contact_card_from_dict(card_dict)
            verify_contact_card(parsed_card)

            await book.add_contact(
                address=parsed_card.address,
                public_key=parsed_card.public_key,
                display_name=parsed_card.display_name,
                trust_state="trusted",
                trust_source="explicit-approval",
            )
            await book.remove_pending("alice::test.local")

            # Send accept
            sender_vk = deserialize_verify_key(parsed_card.public_key)
            await manager._send_accept(bob_agent, "alice::test.local", sender_vk)

            # Verify: contact stored as trusted with explicit-approval
            assert book.is_known("alice::test.local") is True
            assert await book.get_trust_state("alice::test.local") == "trusted"

            async with book._db.execute(
                "SELECT trust_source FROM contacts WHERE address = ?",
                ("alice::test.local",),
            ) as cur:
                row = await cur.fetchone()
                assert row[0] == "explicit-approval"

            # Pending should be empty
            assert len(await book.get_pending()) == 0

            # Accept should have been sent (2nd call -- first was during handle_inbound for approval-required: no send)
            # Actually approval-required does NOT send accept, so this is the first call on bob_agent._transport
            # But handle_inbound for approval-required does NOT call transport.send -- it stores in pending.
            # The _send_accept call above is the only transport.send call.
            bob_agent._transport.send.assert_called_once()
            sent_wire = bob_agent._transport.send.call_args[0][0]
            assert sent_wire["type"] == MessageType.HANDSHAKE_ACCEPT.value
        finally:
            await book.close()


class TestDenyFlow:
    """HAND-02: Deny a pending handshake request."""

    async def test_deny_removes_pending_and_sends_deny(self, data_dir):
        """Denying a pending request removes it and sends handshake.deny."""
        sk_a, vk_a = generate_keypair()
        sk_b, vk_b = generate_keypair()

        book = ContactBook(data_dir)
        await book.open()
        try:
            # Set up: store a pending handshake
            manager = HandshakeManager(book, "approval-required")

            envelope, card = _make_handshake_request_envelope(
                sk_a, vk_a, sk_b, vk_b, "alice::test.local", "bob::test.local"
            )
            bob_agent = _mock_agent(sk_b, vk_b, "bob::test.local")
            await manager.handle_inbound(bob_agent, envelope, vk_a)

            assert len(await book.get_pending()) == 1

            # Simulate deny: get pending, extract card, remove pending, send deny
            pending_list = await book.get_pending()
            entry = pending_list[0]
            card_dict = json.loads(entry["contact_card"])
            parsed_card = contact_card_from_dict(card_dict)
            sender_vk = deserialize_verify_key(parsed_card.public_key)

            await book.remove_pending("alice::test.local")
            await manager._send_deny(bob_agent, "alice::test.local", sender_vk)

            # Verify: NOT in contacts, NOT in pending
            assert book.is_known("alice::test.local") is False
            assert len(await book.get_pending()) == 0

            # Deny should have been sent
            bob_agent._transport.send.assert_called_once()
            sent_wire = bob_agent._transport.send.call_args[0][0]
            assert sent_wire["type"] == MessageType.HANDSHAKE_DENY.value
        finally:
            await book.close()


class TestHandshakeAccept:
    """Receiving handshake.accept stores the contact as trusted."""

    async def test_handshake_accept_stores_contact(self, data_dir):
        """Handshake accept from alice stores her in bob's contact book."""
        sk_a, vk_a = generate_keypair()
        sk_b, vk_b = generate_keypair()

        book = ContactBook(data_dir)
        await book.open()
        try:
            manager = HandshakeManager(book, "auto-accept")

            # Phase 43 T1.2: an accept can only promote to 'pinned' if Bob
            # previously initiated a handshake to Alice. Seed the prior state.
            await book.add_contact(
                address="alice::test.local",
                public_key=serialize_verify_key(vk_a),
                trust_state="handshake-sent",
            )

            # Create a handshake.accept envelope from alice
            accept_payload = json.dumps({"status": "accepted"}).encode("utf-8")
            envelope = create_envelope(
                from_address="alice::test.local",
                to_address="bob::test.local",
                message_type=MessageType.HANDSHAKE_ACCEPT,
                payload_plaintext=accept_payload,
                signing_key=sk_a,
                recipient_verify_key=vk_b,
            )

            bob_agent = _mock_agent(sk_b, vk_b, "bob::test.local")
            result = await manager.handle_inbound(bob_agent, envelope, vk_a)

            assert result is None
            assert book.is_known("alice::test.local") is True
            pk = await book.get_public_key("alice::test.local")
            assert pk == serialize_verify_key(vk_a)
        finally:
            await book.close()


class TestKnownContactSkipsHandshake:
    """HAND-03: Known contacts bypass handshake."""

    async def test_known_contact_skips_handshake(self, data_dir):
        """is_known() returns True for stored contacts -- no handshake needed."""
        sk_a, vk_a = generate_keypair()

        book = ContactBook(data_dir)
        await book.open()
        try:
            await book.add_contact(
                "alice::test.local",
                serialize_verify_key(vk_a),
                trust_state="trusted",
            )
            assert book.is_known("alice::test.local") is True
        finally:
            await book.close()


# ===========================================================================
# Phase 43 — Theme 1: TOFU/SDK card-binding tests (T1.1)
# ===========================================================================
#
# These tests are FAILING-BY-DESIGN as of Wave 0. Plan 01 will turn them green
# by adding card↔envelope binding in HandshakeManager._handle_request and
# Agent.approve.
#
# References:
#   - 43-VALIDATION.md rows T1.1
#   - 43-RESEARCH.md Pattern 3 (TOFU Card-Binding)
#   - REVIEW-protocol-sdk.md finding #1
# ===========================================================================


def _make_handshake_request_envelope_with_card(
    sk_sender,
    vk_sender,
    sk_recipient,
    vk_recipient,
    sender_addr,
    recipient_addr,
    card,
):
    """Build a handshake.request envelope with a *caller-supplied* card.

    Differs from ``_make_handshake_request_envelope`` (top of file) in that
    the caller controls the embedded card identity, allowing adversarial
    fixtures where card.address != envelope.from_address.
    """
    card_json = json.dumps(contact_card_to_dict(card))
    envelope = create_envelope(
        from_address=sender_addr,
        to_address=recipient_addr,
        message_type=MessageType.HANDSHAKE_REQUEST,
        payload_plaintext=card_json.encode("utf-8"),
        signing_key=sk_sender,
        recipient_verify_key=vk_recipient,
    )
    return envelope


async def test_request_rejects_card_address_mismatch(data_dir):
    """T1.1: a handshake.request whose embedded card.address != envelope.from_address must be rejected.

    Setup: Eve crafts a card claiming address='alice::test.local' but signed
    with Eve's key. Eve sends the envelope from 'eve::evil.local'. The card
    is internally self-consistent (verify_contact_card passes — Eve's key
    signs the card). The SDK must reject on the address-mismatch binding.

    Expected behaviour after Plan 01: InvalidEnvelopeError.
    Today (Wave 0): _handle_request happily ingests the forged card and
    stores 'alice::test.local' in Bob's contact book, so this test FAILS.
    """
    from uam.protocol.errors import InvalidEnvelopeError

    sk_eve, vk_eve = generate_keypair()
    sk_bob, vk_bob = generate_keypair()

    # Eve forges a card claiming Alice's address but signs it with her own key
    forged_card = create_contact_card(
        address="alice::test.local",
        display_name="alice",
        relay="ws://test/ws",
        signing_key=sk_eve,
    )
    envelope = _make_handshake_request_envelope_with_card(
        sk_eve, vk_eve, sk_bob, vk_bob,
        sender_addr="eve::evil.local",
        recipient_addr="bob::test.local",
        card=forged_card,
    )

    book = ContactBook(data_dir)
    await book.open()
    try:
        manager = HandshakeManager(book, "auto-accept")
        bob_agent = _mock_agent(sk_bob, vk_bob, "bob::test.local")

        with pytest.raises(InvalidEnvelopeError, match="address.*does not match|does not match.*sender|card.*address"):
            await manager._handle_request(bob_agent, envelope, vk_eve)

        # Side-effect must NOT have happened — alice's address must not appear
        assert book.is_known("alice::test.local") is False
        assert book.is_known("eve::evil.local") is False
    finally:
        await book.close()


async def test_request_rejects_card_pubkey_mismatch(data_dir):
    """T1.1: a contact_card whose embedded public_key differs from the envelope sender's verify key must be rejected.

    Setup: Eve sends the envelope from 'eve::evil.local' signed with her key,
    but embeds a card whose public_key is BOB's key (Eve trying to make Alice
    pin Bob's key for Eve's address). The card is internally self-consistent
    (signed by Bob's key). The SDK must cross-check envelope.sender_vk against
    card.public_key and reject.

    Expected behaviour after Plan 01: InvalidEnvelopeError.
    Today (Wave 0): _handle_request only calls verify_contact_card (which
    only checks self-signature) and ingests the mismatched card, so this
    test FAILS.
    """
    from uam.protocol.errors import InvalidEnvelopeError

    sk_eve, vk_eve = generate_keypair()
    sk_bob, vk_bob = generate_keypair()
    sk_alice, vk_alice = generate_keypair()

    # Eve crafts a card matching her envelope address but signed with BOB's key,
    # so card.public_key == BOB's key (passes verify_contact_card)
    forged_card = create_contact_card(
        address="eve::evil.local",
        display_name="eve",
        relay="ws://test/ws",
        signing_key=sk_bob,
    )
    envelope = _make_handshake_request_envelope_with_card(
        sk_eve, vk_eve, sk_alice, vk_alice,
        sender_addr="eve::evil.local",
        recipient_addr="alice::test.local",
        card=forged_card,
    )

    book = ContactBook(data_dir)
    await book.open()
    try:
        manager = HandshakeManager(book, "auto-accept")
        alice_agent = _mock_agent(sk_alice, vk_alice, "alice::test.local")

        with pytest.raises(InvalidEnvelopeError, match="public_key.*does not match|verify key|card.*key|key.*does not match"):
            await manager._handle_request(alice_agent, envelope, vk_eve)

        # Eve's address must NOT have been pinned with Bob's key
        assert book.is_known("eve::evil.local") is False
    finally:
        await book.close()


async def test_approve_rejects_mismatched_card(data_dir, tmp_path, monkeypatch):
    """T1.1: Agent.approve() must enforce the same card↔envelope binding as _handle_request.

    The pending handshake holds a contact_card; approve() should re-validate
    the card before promoting to trusted. We seed pending_handshakes with a
    card whose address differs from the pending entry's address (simulating
    a request that slipped through the request-handler binding gate, or a
    historical pending row from before the fix landed).

    Expected behaviour after Plan 01: InvalidEnvelopeError on approve().
    Today (Wave 0): Agent.approve only calls verify_contact_card and trusts
    the embedded card, so this test FAILS.
    """
    from uam.protocol.errors import InvalidEnvelopeError
    from uam.sdk.agent import Agent

    # Isolate from any real ~/.uam state
    monkeypatch.setenv("UAM_HOME", str(tmp_path / "uam_home"))

    sk_eve, vk_eve = generate_keypair()

    # Build a self-consistent card claiming a different address than the
    # pending entry's address. verify_contact_card will pass; the binding
    # check must reject.
    bad_card = create_contact_card(
        address="alice::test.local",  # Eve forging Alice
        display_name="alice",
        relay="ws://test/ws",
        signing_key=sk_eve,
    )

    # Build a minimal Agent and seed the pending row directly
    agent = Agent(
        "bob",
        relay="http://testserver",
        key_dir=str(tmp_path / "keys"),
        auto_register=False,
        transport="http",
    )
    agent._key_manager.load_or_generate("bob")
    # approve() uses _send_accept which reads agent.address — set _address
    # so the post-binding-check code path doesn't trip on RuntimeError.
    agent._address = "bob::test.local"
    # _send_accept also calls self._transport.send, so install a stub
    agent._transport = AsyncMock()
    await agent._contact_book.open()
    try:
        # Seed pending: address key is 'eve::evil.local' (envelope sender)
        # but the stored card claims 'alice::test.local'
        await agent._contact_book.add_pending(
            "eve::evil.local",
            json.dumps(contact_card_to_dict(bad_card)),
        )
        agent._connected = True

        with pytest.raises(InvalidEnvelopeError, match="does not match|public_key|address|card"):
            await agent.approve("eve::evil.local")

        # Neither address should have been promoted to trusted
        assert agent._contact_book.is_known("alice::test.local") is False
        assert agent._contact_book.is_known("eve::evil.local") is False
    finally:
        await agent._contact_book.close()

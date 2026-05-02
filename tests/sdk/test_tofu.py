"""Tests for TOFU (Trust On First Use) key pinning (TOFU-01 through TOFU-05)."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import aiosqlite
import pytest

from uam.protocol import (
    MessageType,
    UAMError,
    create_envelope,
    create_contact_card,
    contact_card_to_dict,
    generate_keypair,
    serialize_verify_key,
    deserialize_verify_key,
)
from uam.protocol.errors import KeyPinningError
from uam.sdk.contact_book import ContactBook
from uam.sdk.handshake import HandshakeManager


@pytest.fixture()
def data_dir(tmp_path):
    """Temporary data directory for TOFU tests."""
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


class TestTOFUResolvePublicKey:
    """TOFU-01: Known contacts resolved locally with zero network I/O."""

    async def test_pinned_contact_resolved_locally(self, data_dir):
        """A pinned contact's key is returned from ContactBook without network call."""
        sk_a, vk_a = generate_keypair()
        sk_b, vk_b = generate_keypair()
        pk_b_str = serialize_verify_key(vk_b)

        book = ContactBook(data_dir)
        await book.open()
        try:
            # Add a pinned contact
            await book.add_contact(
                "bob::test.local", pk_b_str, trust_state="pinned"
            )

            # Create a mock agent with the contact book
            from uam.sdk.agent import Agent
            agent = Agent.__new__(Agent)
            agent._contact_book = book
            agent._resolver = AsyncMock()

            result = await agent._resolve_public_key("bob::test.local")

            # Should return the stored key
            assert serialize_verify_key(result) == pk_b_str
            # Resolver should NOT have been called
            agent._resolver.resolve_public_key.assert_not_called()
        finally:
            await book.close()

    async def test_provisional_contact_resolved_locally(self, data_dir):
        """A provisional contact's key is returned without network call."""
        sk_a, vk_a = generate_keypair()
        sk_b, vk_b = generate_keypair()
        pk_b_str = serialize_verify_key(vk_b)

        book = ContactBook(data_dir)
        await book.open()
        try:
            await book.add_contact(
                "bob::test.local", pk_b_str, trust_state="provisional"
            )

            from uam.sdk.agent import Agent
            agent = Agent.__new__(Agent)
            agent._contact_book = book
            agent._resolver = AsyncMock()

            result = await agent._resolve_public_key("bob::test.local")

            assert serialize_verify_key(result) == pk_b_str
            agent._resolver.resolve_public_key.assert_not_called()
        finally:
            await book.close()

    async def test_unknown_contact_resolved_without_mutation(self, data_dir):
        """T1.5: _resolve_public_key is PURE -- it must NOT mutate the contact book.

        Phase 43 T1.5 (Plan 02): the resolver returns the key without writing
        any row to the contact book. This is the fix that makes send()'s
        first-contact handshake actually fire (the old behaviour wrote a
        ``provisional`` row here, which made send()'s ``is_known()`` check
        short-circuit and skip ``_initiate_handshake``). Provisional /
        handshake-sent storage now lives inside ``_initiate_handshake``.

        Pre-Plan-02 this test asserted ``trust == 'provisional'`` after
        ``_resolve_public_key`` ran -- that assertion encoded the bug. The
        corrected contract is: resolver returns the key, contact book is
        unchanged.
        """
        sk_b, vk_b = generate_keypair()
        pk_b_str = serialize_verify_key(vk_b)

        book = ContactBook(data_dir)
        await book.open()
        try:
            from uam.sdk.agent import Agent
            agent = Agent.__new__(Agent)
            agent._contact_book = book
            agent._resolver = AsyncMock()
            agent._token = "test-token"
            agent._config = MagicMock()
            agent._config.relay_url = "http://testserver"

            # Mock resolver returns a key
            agent._resolver.resolve_public_key = AsyncMock(return_value=pk_b_str)

            # Pre-condition: bob is unknown
            assert book.is_known("bob::test.local") is False
            assert await book.get_trust_state("bob::test.local") is None

            result = await agent._resolve_public_key("bob::test.local")

            # The key is returned correctly
            assert serialize_verify_key(result) == pk_b_str
            agent._resolver.resolve_public_key.assert_called_once()

            # T1.5 contract: the contact book must NOT have been mutated.
            # No row, no trust state, is_known still False.
            assert book.is_known("bob::test.local") is False
            assert await book.get_trust_state("bob::test.local") is None
            assert await book.get_public_key("bob::test.local") is None
        finally:
            await book.close()


class TestTOFUKeyMismatch:
    """TOFU-03: Key mismatch detection for pinned contacts."""

    async def test_pinned_key_mismatch_raises_error(self, data_dir):
        """A race-condition mismatch for a pinned contact raises KeyPinningError."""
        sk_real, vk_real = generate_keypair()
        sk_fake, vk_fake = generate_keypair()
        pk_real_str = serialize_verify_key(vk_real)
        pk_fake_str = serialize_verify_key(vk_fake)

        book = ContactBook(data_dir)
        await book.open()
        try:
            from uam.sdk.agent import Agent
            agent = Agent.__new__(Agent)
            agent._contact_book = book
            agent._resolver = AsyncMock()
            agent._token = "test-token"
            agent._config = MagicMock()
            agent._config.relay_url = "http://testserver"

            # Resolver returns a fake key
            agent._resolver.resolve_public_key = AsyncMock(return_value=pk_fake_str)

            # Simulate: get_public_key returns None first, then between resolve
            # and the second check, a pinned contact appears with the real key.
            original_get_pk = book.get_public_key
            call_count = 0

            async def side_effect_get_pk(address):
                nonlocal call_count
                call_count += 1
                if call_count == 1:
                    return None  # First check: unknown
                # Second check: now pinned (simulates race)
                return pk_real_str

            original_get_trust = book.get_trust_state

            with patch.object(book, 'get_public_key', side_effect=side_effect_get_pk):
                with patch.object(book, 'get_trust_state', return_value="pinned"):
                    with pytest.raises(KeyPinningError, match="CRITICAL"):
                        await agent._resolve_public_key("bob::test.local")
        finally:
            await book.close()

    async def test_trusted_key_mismatch_raises_error(self, data_dir):
        """Grandfathered 'trusted' contacts also get mismatch protection."""
        sk_real, vk_real = generate_keypair()
        sk_fake, vk_fake = generate_keypair()
        pk_real_str = serialize_verify_key(vk_real)
        pk_fake_str = serialize_verify_key(vk_fake)

        book = ContactBook(data_dir)
        await book.open()
        try:
            from uam.sdk.agent import Agent
            agent = Agent.__new__(Agent)
            agent._contact_book = book
            agent._resolver = AsyncMock()
            agent._token = "test-token"
            agent._config = MagicMock()
            agent._config.relay_url = "http://testserver"

            agent._resolver.resolve_public_key = AsyncMock(return_value=pk_fake_str)

            call_count = 0

            async def side_effect_get_pk(address):
                nonlocal call_count
                call_count += 1
                if call_count == 1:
                    return None
                return pk_real_str

            with patch.object(book, 'get_public_key', side_effect=side_effect_get_pk):
                with patch.object(book, 'get_trust_state', return_value="trusted"):
                    with pytest.raises(KeyPinningError, match="CRITICAL"):
                        await agent._resolve_public_key("bob::test.local")
        finally:
            await book.close()


class TestTOFUHandshakeLifecycle:
    """TOFU-02: Handshake trust state lifecycle (provisional -> pinned)."""

    async def test_handshake_request_stores_provisional(self, data_dir):
        """A handshake request arrival stores contact as provisional."""
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

            result = await manager.handle_inbound(bob_agent, envelope, vk_a)
            assert result is None

            # Contact should be stored as provisional
            trust = await book.get_trust_state("alice::test.local")
            assert trust == "provisional"

            # Verify trust_source
            async with book._db.execute(
                "SELECT trust_source FROM contacts WHERE address = ?",
                ("alice::test.local",),
            ) as cur:
                row = await cur.fetchone()
                assert row[0] == "auto-accepted-provisional"
        finally:
            await book.close()

    async def test_handshake_accept_upgrades_to_pinned(self, data_dir):
        """After handshake accept, trust_state is 'pinned' and pinned_at is set."""
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

            # Trust state should be pinned
            trust = await book.get_trust_state("alice::test.local")
            assert trust == "pinned"

            # pinned_at should be set
            async with book._db.execute(
                "SELECT pinned_at FROM contacts WHERE address = ?",
                ("alice::test.local",),
            ) as cur:
                row = await cur.fetchone()
                assert row[0] is not None  # Has a timestamp
        finally:
            await book.close()


class TestRequireVerifyPolicy:
    """TOFU-05: require_verify trust policy gate in send()."""

    async def test_require_verify_blocks_provisional(self, data_dir):
        """require_verify policy raises UAMError for provisional contacts."""
        sk_a, vk_a = generate_keypair()
        sk_b, vk_b = generate_keypair()
        pk_b_str = serialize_verify_key(vk_b)

        book = ContactBook(data_dir)
        await book.open()
        try:
            await book.add_contact(
                "bob::test.local", pk_b_str, trust_state="provisional"
            )

            from uam.sdk.agent import Agent
            agent = Agent.__new__(Agent)
            agent._contact_book = book
            agent._config = MagicMock()
            agent._config.trust_policy = "require_verify"
            agent._connected = True

            with pytest.raises(UAMError, match="require_verify"):
                await agent.send("bob::test.local", "Hello")
        finally:
            await book.close()

    async def test_require_verify_allows_pinned(self, data_dir):
        """require_verify policy allows sending to pinned contacts."""
        sk_a, vk_a = generate_keypair()
        sk_b, vk_b = generate_keypair()
        pk_b_str = serialize_verify_key(vk_b)

        book = ContactBook(data_dir)
        await book.open()
        try:
            await book.add_contact(
                "bob::test.local", pk_b_str, trust_state="pinned"
            )

            from uam.sdk.agent import Agent
            agent = Agent.__new__(Agent)
            agent._contact_book = book
            agent._config = MagicMock()
            agent._config.trust_policy = "require_verify"
            agent._config.relay_url = "http://testserver"
            agent._config.relay_ws_url = "ws://testserver/ws"
            agent._config.display_name = "testbot"
            agent._connected = True
            agent._address = "testbot::test.local"
            agent._key_manager = MagicMock()
            agent._key_manager.signing_key = sk_a
            agent._resolver = AsyncMock()
            agent._transport = AsyncMock()
            agent._token = "test-token"

            # send() should pass the require_verify gate (pinned is allowed)
            # It will proceed to _resolve_public_key which returns stored key,
            # then try to send. We mock transport to succeed.
            await agent.send("bob::test.local", "Hello")

            # Transport should have been called (message sent)
            agent._transport.send.assert_called()
        finally:
            await book.close()

    async def test_require_verify_allows_verified(self, data_dir):
        """require_verify policy allows sending to verified contacts."""
        sk_a, vk_a = generate_keypair()
        sk_b, vk_b = generate_keypair()
        pk_b_str = serialize_verify_key(vk_b)

        book = ContactBook(data_dir)
        await book.open()
        try:
            await book.add_contact(
                "bob::test.local", pk_b_str, trust_state="verified"
            )

            from uam.sdk.agent import Agent
            agent = Agent.__new__(Agent)
            agent._contact_book = book
            agent._config = MagicMock()
            agent._config.trust_policy = "require_verify"
            agent._config.relay_url = "http://testserver"
            agent._config.relay_ws_url = "ws://testserver/ws"
            agent._config.display_name = "testbot"
            agent._connected = True
            agent._address = "testbot::test.local"
            agent._key_manager = MagicMock()
            agent._key_manager.signing_key = sk_a
            agent._resolver = AsyncMock()
            agent._transport = AsyncMock()
            agent._token = "test-token"

            await agent.send("bob::test.local", "Hello")
            agent._transport.send.assert_called()
        finally:
            await book.close()


class TestMigrationV3:
    """ContactBook migration v3 adds pinned_at column."""

    async def test_migration_v3_adds_pinned_at(self, data_dir):
        """Opening ContactBook on a v2 database adds pinned_at column."""
        db_path = data_dir / "contacts" / "contacts.db"
        db_path.parent.mkdir(parents=True, exist_ok=True)

        # Create a v2 database manually
        db = await aiosqlite.connect(str(db_path))
        await db.executescript("""
            CREATE TABLE IF NOT EXISTS contacts (
                address      TEXT PRIMARY KEY,
                public_key   TEXT NOT NULL,
                display_name TEXT,
                trust_state  TEXT NOT NULL DEFAULT 'unknown',
                first_seen   TEXT NOT NULL DEFAULT (datetime('now')),
                last_seen    TEXT NOT NULL DEFAULT (datetime('now')),
                trust_source TEXT DEFAULT 'legacy-unknown',
                relay        TEXT,
                relays_json  TEXT
            );
            CREATE TABLE IF NOT EXISTS pending_handshakes (
                address      TEXT PRIMARY KEY,
                contact_card TEXT NOT NULL,
                received_at  TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS blocked_patterns (
                pattern     TEXT PRIMARY KEY,
                blocked_at  TEXT NOT NULL DEFAULT (datetime('now'))
            );
        """)
        await db.execute("PRAGMA user_version = 2")
        await db.commit()
        await db.close()

        # Open with ContactBook -- migration should add pinned_at
        book = ContactBook(data_dir)
        await book.open()
        try:
            async with book._db.execute(
                "PRAGMA table_info(contacts)"
            ) as cur:
                columns = [row[1] for row in await cur.fetchall()]
                assert "pinned_at" in columns

            # Verify version is now 3
            async with book._db.execute("PRAGMA user_version") as cur:
                version = (await cur.fetchone())[0]
                assert version == 3
        finally:
            await book.close()

    async def test_fresh_database_has_pinned_at(self, data_dir):
        """A fresh database includes the pinned_at column after all migrations."""
        book = ContactBook(data_dir)
        await book.open()
        try:
            async with book._db.execute(
                "PRAGMA table_info(contacts)"
            ) as cur:
                columns = [row[1] for row in await cur.fetchall()]
                assert "pinned_at" in columns

            async with book._db.execute("PRAGMA user_version") as cur:
                version = (await cur.fetchone())[0]
                assert version == 3
        finally:
            await book.close()


class TestIsTrustedOrVerifiedIncludesPinned:
    """is_trusted_or_verified now includes 'pinned' state."""

    async def test_is_trusted_or_verified_includes_pinned(self, data_dir):
        """A contact with trust_state='pinned' is considered trusted."""
        book = ContactBook(data_dir)
        await book.open()
        try:
            await book.add_contact(
                "alice::test.local", "key-a", trust_state="pinned"
            )
            assert await book.is_trusted_or_verified("alice::test.local") is True
        finally:
            await book.close()

    async def test_provisional_not_trusted_or_verified(self, data_dir):
        """A provisional contact is NOT trusted or verified."""
        book = ContactBook(data_dir)
        await book.open()
        try:
            await book.add_contact(
                "alice::test.local", "key-a", trust_state="provisional"
            )
            assert await book.is_trusted_or_verified("alice::test.local") is False
        finally:
            await book.close()


# ===========================================================================
# Phase 43 — Theme 1: Unsolicited handshake.accept tests (T1.2)
# ===========================================================================
#
# These tests are FAILING-BY-DESIGN as of Wave 0. Plan 01 will turn them green
# by gating _handle_accept on prior 'handshake-sent' state and verifying the
# embedded contact_card matches the envelope sender.
#
# References:
#   - 43-VALIDATION.md rows T1.2
#   - 43-RESEARCH.md Pattern 3 (TOFU Card-Binding) + phase_requirements T1.2
#   - REVIEW-protocol-sdk.md finding #2
# ===========================================================================


async def test_unsolicited_accept_rejected(data_dir):
    """T1.2: an inbound handshake.accept from an address that we never sent a
    handshake.request to must NOT promote that address to 'pinned'.

    Expected behaviour after Plan 01: _handle_accept short-circuits when the
    prior trust_state is not 'handshake-sent' (logs a warning, drops the
    envelope, does NOT pin).
    Today (Wave 0): _handle_accept unconditionally calls add_contact with
    trust_state='pinned', so this test FAILS — the assertion that state
    != 'pinned' will not hold.
    """
    sk_eve, vk_eve = generate_keypair()
    sk_alice, vk_alice = generate_keypair()

    # Build a handshake.accept envelope from Eve to Alice. Alice has never
    # sent a request to Eve, so this is unsolicited.
    accept_payload = json.dumps({"status": "accepted"}).encode("utf-8")
    accept_envelope = create_envelope(
        from_address="eve::evil.local",
        to_address="alice::test.local",
        message_type=MessageType.HANDSHAKE_ACCEPT,
        payload_plaintext=accept_payload,
        signing_key=sk_eve,
        recipient_verify_key=vk_alice,
    )

    book = ContactBook(data_dir)
    await book.open()
    try:
        manager = HandshakeManager(book, "auto-accept")
        alice_agent = _mock_agent(sk_alice, vk_alice, "alice::test.local")

        # Pre-condition: Alice has NEVER sent a handshake.request to Eve
        assert await book.get_trust_state("eve::evil.local") is None

        # Process the unsolicited accept. After Plan 01, _handle_accept's
        # signature is (agent, envelope, sender_vk).
        await manager._handle_accept(alice_agent, accept_envelope, vk_eve)

        # Post-condition: must NOT be pinned. Failure mode today: state == 'pinned'.
        state = await book.get_trust_state("eve::evil.local")
        assert state != "pinned", (
            f"Unsolicited handshake.accept promoted Eve to pinned (state={state!r}). "
            "After Plan 01, _handle_accept must reject when prior state is not 'handshake-sent'."
        )
    finally:
        await book.close()


async def test_accept_card_envelope_binding(data_dir):
    """T1.2: handshake.accept must cross-check the embedded contact_card against the envelope.

    Setup: Alice DID send a request to Bob (trust_state='handshake-sent'),
    but the inbound accept arrives from Bob's address with an embedded
    contact_card claiming Eve's identity. The SDK must reject the accept
    rather than promote Bob to pinned (or worse, accept Eve's identity).

    Expected behaviour after Plan 01: InvalidEnvelopeError (or equivalent
    rejection that leaves Bob in 'handshake-sent').
    Today (Wave 0): _handle_accept ignores the payload entirely, so the
    embedded card is never inspected and the test FAILS — Bob is promoted
    to pinned with no binding check.
    """
    from uam.protocol.errors import InvalidEnvelopeError

    sk_bob, vk_bob = generate_keypair()
    sk_eve, vk_eve = generate_keypair()
    sk_alice, vk_alice = generate_keypair()

    book = ContactBook(data_dir)
    await book.open()
    try:
        # Step 1: Alice has sent a request to Bob — establish handshake-sent state
        await book.add_contact(
            address="bob::test.local",
            public_key=serialize_verify_key(vk_bob),
            trust_state="handshake-sent",
        )
        manager = HandshakeManager(book, "auto-accept")

        # Step 2: build an accept envelope from Bob whose embedded card
        # actually claims Eve's identity (eve::evil.local, eve's pubkey)
        forged_card = create_contact_card(
            address="eve::evil.local",
            display_name="eve",
            relay="ws://test/ws",
            signing_key=sk_eve,
        )
        accept_payload = json.dumps({
            "status": "accepted",
            "contact_card": contact_card_to_dict(forged_card),
        }).encode("utf-8")
        envelope = create_envelope(
            from_address="bob::test.local",
            to_address="alice::test.local",
            message_type=MessageType.HANDSHAKE_ACCEPT,
            payload_plaintext=accept_payload,
            signing_key=sk_bob,
            recipient_verify_key=vk_alice,
        )
        alice_agent = _mock_agent(sk_alice, vk_alice, "alice::test.local")

        with pytest.raises(InvalidEnvelopeError, match="card|address|public_key|does not match"):
            await manager._handle_accept(alice_agent, envelope, vk_bob)

        # Bob remains in handshake-sent (NOT promoted to pinned)
        state = await book.get_trust_state("bob::test.local")
        assert state == "handshake-sent", (
            f"Bob's trust_state should remain 'handshake-sent' after a card-mismatched "
            f"accept; got {state!r}"
        )
        # Eve must not have been added either
        assert book.is_known("eve::evil.local") is False
    finally:
        await book.close()

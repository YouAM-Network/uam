"""T3.1 — _process_inbound replay-window adversarial tests (Wave 0, failing-by-design).

Tests assert the FOUR new checks Plan 45-01 must inject into ``_process_inbound``
AFTER ``verify_envelope`` succeeds and BEFORE handshake handling:

  (a) recipient binding: ``to_address != self._address`` → drop
  (b) timestamp freshness: ``|now - timestamp| > MAX_ENVELOPE_AGE`` → drop
  (c) explicit expiry: ``now > expires`` (if present) → drop
  (d) replay cache: ``(from_address, message_id)`` already seen → drop

PLUS the order-discipline check: replays do NOT trigger auto-receipts
(RESEARCH § Pitfall 4).  The auto-receipt loop in ``Agent.inbox`` only runs
on results that ``_process_inbound`` returns; if replay rejection returns
None, no receipt fires.  This test instead drives ``_process_inbound``
directly twice and confirms exactly one ``ReceivedMessage`` surfaces.

These tests use the same in-process construction pattern as
``tests/sdk/test_send_inbox.py::TestProcessInbound`` (no real relay).
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from uam.protocol import (
    MessageType,
    create_envelope,
    generate_keypair,
    serialize_verify_key,
    to_wire_dict,
)
from uam.sdk.agent import Agent


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _make_recipient_agent(tmp_path, name: str = "bob"):
    """Construct an in-process Agent (no relay) with its contact book open.

    Mirrors ``tests/sdk/test_send_inbox.py::TestProcessInbound._make_agent_with_contact_book``.
    Caller is responsible for ``await agent._contact_book.close()``.
    """
    agent = Agent(
        name,
        relay="http://testserver",
        key_dir=str(tmp_path / "keys"),
        auto_register=False,
        transport="http",
    )
    agent._key_manager.load_or_generate(name)
    agent._address = f"{name}::test.local"
    await agent._contact_book.open()
    return agent


def _build_signed_envelope(
    sender_signing_key,
    sender_verify_key,
    recipient_verify_key,
    sender_address: str,
    recipient_address: str,
    *,
    timestamp: str | None = None,
    expires: str | None = None,
):
    """Construct a fully-signed Envelope using the existing ``create_envelope`` API.

    For deterministic timestamp/expires control we post-process the resulting
    envelope via ``dataclasses.replace`` and re-sign — ``create_envelope`` always
    stamps ``utc_timestamp()`` itself, so we have to override AFTER.
    """
    from dataclasses import replace
    from uam.protocol.envelope import _build_signable_dict
    from uam.protocol.crypto import canonicalize, sign_message

    envelope = create_envelope(
        from_address=sender_address,
        to_address=recipient_address,
        message_type=MessageType.MESSAGE,
        payload_plaintext=b"hello",
        signing_key=sender_signing_key,
        recipient_verify_key=recipient_verify_key,
    )

    if timestamp is None and expires is None:
        return envelope

    # Override timestamp/expires and re-sign so the signature is still valid.
    overridden = replace(
        envelope,
        timestamp=timestamp if timestamp is not None else envelope.timestamp,
        expires=expires if expires is not None else envelope.expires,
        signature="",
    )
    signable = _build_signable_dict(overridden)
    new_sig = sign_message(canonicalize(signable), sender_signing_key)
    return replace(overridden, signature=new_sig)


# ---------------------------------------------------------------------------
# (a) Recipient binding
# ---------------------------------------------------------------------------


async def test_recipient_mismatch_dropped(tmp_path):
    """Envelope addressed to someone OTHER than self must be dropped.

    Today (Wave 0): ``_process_inbound`` does not check ``to_address``; it
    decrypts whatever the relay handed over and surfaces it to user code.
    Plan 45-01 must add a recipient-binding check that compares
    ``envelope.to_address`` against ``self._address`` and drops mismatches.
    """
    sk_a, vk_a = generate_keypair()
    bob = await _make_recipient_agent(tmp_path, "bob")
    try:
        await bob._contact_book.add_contact(
            "alice::test.local", serialize_verify_key(vk_a)
        )
        # Build envelope addressed to a DIFFERENT recipient (not bob)
        env = _build_signed_envelope(
            sk_a,
            vk_a,
            bob._key_manager.verify_key,
            "alice::test.local",
            "wrong-recipient::test.local",
        )
        wire = to_wire_dict(env)
        msg = await bob._process_inbound(wire)
        assert msg is None, (
            "envelope addressed to someone else must be dropped (recipient binding)"
        )
    finally:
        await bob._contact_book.close()


# ---------------------------------------------------------------------------
# (b) Timestamp freshness
# ---------------------------------------------------------------------------


async def test_stale_envelope_dropped(tmp_path):
    """Envelope with timestamp older than MAX_ENVELOPE_AGE must be dropped.

    Today (Wave 0): timestamps are accepted regardless of age — a relay
    operator who logs ciphertext could replay a message-id-rotated envelope
    months later.  Plan 45-01 must reject envelopes whose timestamp is more
    than ~5 minutes from local clock.
    """
    sk_a, vk_a = generate_keypair()
    bob = await _make_recipient_agent(tmp_path, "bob")
    try:
        await bob._contact_book.add_contact(
            "alice::test.local", serialize_verify_key(vk_a)
        )
        stale_ts = (datetime.now(timezone.utc) - timedelta(seconds=600)).isoformat().replace("+00:00", "Z")
        env = _build_signed_envelope(
            sk_a,
            vk_a,
            bob._key_manager.verify_key,
            "alice::test.local",
            bob._address,
            timestamp=stale_ts,
        )
        wire = to_wire_dict(env)
        msg = await bob._process_inbound(wire)
        assert msg is None, "envelope with timestamp >300s old must be dropped"
    finally:
        await bob._contact_book.close()


# ---------------------------------------------------------------------------
# (c) Explicit expiry
# ---------------------------------------------------------------------------


async def test_expired_envelope_dropped(tmp_path):
    """Envelope with explicit ``expires`` in the past must be dropped.

    Today (Wave 0): the SDK side of expiry is not enforced on inbound — the
    relay sweep handles outbound TTL, but a poisoned relay could replay a
    long-ago expired envelope and the SDK would happily decode it.
    """
    sk_a, vk_a = generate_keypair()
    bob = await _make_recipient_agent(tmp_path, "bob")
    try:
        await bob._contact_book.add_contact(
            "alice::test.local", serialize_verify_key(vk_a)
        )
        past_expires = (datetime.now(timezone.utc) - timedelta(seconds=10)).isoformat().replace("+00:00", "Z")
        env = _build_signed_envelope(
            sk_a,
            vk_a,
            bob._key_manager.verify_key,
            "alice::test.local",
            bob._address,
            expires=past_expires,
        )
        wire = to_wire_dict(env)
        msg = await bob._process_inbound(wire)
        assert msg is None, "envelope with expires in the past must be dropped"
    finally:
        await bob._contact_book.close()


# ---------------------------------------------------------------------------
# (d) Replay cache
# ---------------------------------------------------------------------------


async def test_replayed_envelope_dropped(tmp_path):
    """Same (from_address, message_id) delivered twice — second is a replay.

    Today (Wave 0): the SDK has no inbound replay cache.  The same wire bytes
    handed to ``_process_inbound`` twice produce TWO ``ReceivedMessage``
    objects.  Plan 45-01 introduces ``EnvelopeReplayCache`` and consults it
    AFTER ``verify_envelope`` succeeds (Pitfall 1: never let the cache act
    on unverified envelopes lest a forger DoS the cache).
    """
    sk_a, vk_a = generate_keypair()
    bob = await _make_recipient_agent(tmp_path, "bob")
    try:
        await bob._contact_book.add_contact(
            "alice::test.local", serialize_verify_key(vk_a)
        )
        env = _build_signed_envelope(
            sk_a,
            vk_a,
            bob._key_manager.verify_key,
            "alice::test.local",
            bob._address,
        )
        wire = to_wire_dict(env)
        msg1 = await bob._process_inbound(wire)
        msg2 = await bob._process_inbound(wire)
        assert msg1 is not None, "first delivery must succeed"
        assert msg2 is None, (
            "second delivery (same message_id) must be dropped as replay"
        )
    finally:
        await bob._contact_book.close()


# ---------------------------------------------------------------------------
# Order discipline: replay rejection MUST NOT fire auto-receipt.read
# ---------------------------------------------------------------------------


async def test_replay_no_auto_receipt(tmp_path, monkeypatch):
    """Replayed envelope must NOT trigger auto-receipt.read.

    Pitfall 4: the cache check has to be inside ``_process_inbound`` (return
    None), NOT inside ``inbox()`` after the receipt fires.  We verify this
    by spying on ``_send_read_receipt`` and confirming it sees the legitimate
    delivery exactly once across one valid call + one replay call.
    """
    sk_a, vk_a = generate_keypair()
    bob = await _make_recipient_agent(tmp_path, "bob")
    try:
        await bob._contact_book.add_contact(
            "alice::test.local", serialize_verify_key(vk_a)
        )

        receipt_calls: list[str] = []
        original = bob._send_read_receipt

        async def spy(msg):
            receipt_calls.append(msg.message_id)
            # Don't actually fire — no transport hooked up
            return

        monkeypatch.setattr(bob, "_send_read_receipt", spy)

        env = _build_signed_envelope(
            sk_a,
            vk_a,
            bob._key_manager.verify_key,
            "alice::test.local",
            bob._address,
        )
        wire = to_wire_dict(env)

        # Mimic the inbox() loop: process, then fire auto-receipt iff non-None
        msg1 = await bob._process_inbound(wire)
        if msg1 is not None:
            await bob._send_read_receipt(msg1)
        msg2 = await bob._process_inbound(wire)
        if msg2 is not None:
            await bob._send_read_receipt(msg2)

        assert len(receipt_calls) <= 1, (
            f"replay must not trigger auto-receipt; got {len(receipt_calls)} receipts. "
            "Plan 45-01 must drop the replay inside _process_inbound (return None) "
            "so the inbox() auto-receipt loop never sees it."
        )
    finally:
        await bob._contact_book.close()

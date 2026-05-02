"""First-contact handshake flow manager (HAND-01 through HAND-04).

Handles the three-phase handshake:
  1. HANDSHAKE_REQUEST: sender sends contact card (encrypted with SealedBox)
  2. HANDSHAKE_ACCEPT: recipient stores contact and sends accept back
  3. HANDSHAKE_DENY: recipient rejects the handshake

The HandshakeManager works with the ContactBook to persist trust decisions.

Phase 43 hardening (T1.1, T1.2):
  - Contact cards are bound to their envelope sender via
    :func:`_bind_card_to_envelope`: the card's claimed address and public_key
    must match the envelope's ``from_address`` and signing verify key.
  - ``handshake.accept`` is gated on prior trust_state == ``handshake-sent``;
    unsolicited accepts are dropped to prevent attackers from pinning
    themselves into a recipient's contact book.
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING

from nacl.signing import VerifyKey

from uam.protocol import (
    MessageType,
    create_contact_card,
    create_envelope,
    contact_card_to_dict,
    contact_card_from_dict,
    verify_contact_card,
    decrypt_payload,
    decrypt_payload_anonymous,
    deserialize_verify_key,
    serialize_verify_key,
    to_wire_dict,
    MessageEnvelope,
)
from uam.protocol.errors import InvalidEnvelopeError
from uam.sdk.contact_book import ContactBook
from uam.sdk.message import ReceivedMessage

if TYPE_CHECKING:
    from uam.sdk.agent import Agent

logger = logging.getLogger(__name__)


def _bind_card_to_envelope(card, envelope, sender_vk: VerifyKey) -> None:
    """Verify a contact card's claimed identity is bound to the envelope sender.

    Phase 43 T1.1: a contact_card embedded in a handshake envelope MUST be
    cryptographically bound to the envelope's signer. Without this binding, a
    malicious sender can pre-position a poisoned ``pinned`` contact in the
    recipient's contact book by signing an envelope from their OWN address but
    embedding a card claiming to be SOMEONE ELSE's address with the attacker's
    (or another party's) key.

    Two checks:

    1. ``card.address == envelope.from_address`` -- the card cannot claim
       someone else's address.
    2. ``card.public_key == serialize(sender_vk)`` -- the card's public_key
       must match the verify key actually used to sign the envelope.

    Args:
        card: The deserialized :class:`ContactCard` (already self-signature
            verified via ``verify_contact_card``).
        envelope: An object with a ``from_address`` attribute. Typically a
            :class:`MessageEnvelope` but any duck-typed object works (used
            by ``Agent.approve`` to re-validate stored pending entries).
        sender_vk: The Ed25519 :class:`VerifyKey` used to authenticate the
            envelope's signature. For request handling this is the key the
            transport layer resolved; for ``Agent.approve`` it is derived
            from the stored card.

    Raises:
        InvalidEnvelopeError: If either binding check fails.
    """
    if card.address != envelope.from_address:
        raise InvalidEnvelopeError(
            f"Contact card address {card.address!r} does not match envelope "
            f"sender {envelope.from_address!r}"
        )
    card_vk = deserialize_verify_key(card.public_key)
    if card_vk.encode() != sender_vk.encode():
        raise InvalidEnvelopeError(
            "Contact card public_key does not match envelope sender's verify key"
        )


class HandshakeManager:
    """Manages first-contact handshake flow.

    Trust policies:
      - ``"auto-accept"``: Automatically store contact and send accept (HAND-04)
      - ``"approval-required"``: Store in pending_handshakes for manual review
      - ``"allowlist-only"``: Auto-deny unknown senders; only pre-approved contacts allowed
    """

    def __init__(self, contact_book: ContactBook, trust_policy: str) -> None:
        self._contact_book = contact_book
        self._trust_policy = trust_policy

    async def create_handshake_request(
        self,
        agent: Agent,
        to_address: str,
        recipient_vk: VerifyKey,
    ) -> dict:
        """Create a handshake request envelope with embedded contact card.

        The payload is the JSON-serialized contact card, encrypted with
        SealedBox (anonymous encryption) to the recipient.

        Returns:
            Wire-format dict ready to send via transport.
        """
        # Create contact card for the sending agent
        card = create_contact_card(
            address=agent.address,
            display_name=agent._config.display_name,
            relay=agent._config.relay_ws_url,
            signing_key=agent._key_manager.signing_key,
        )
        card_json = json.dumps(contact_card_to_dict(card))

        # Create envelope -- create_envelope auto-uses SealedBox for
        # HANDSHAKE_REQUEST message type
        envelope = create_envelope(
            from_address=agent.address,
            to_address=to_address,
            message_type=MessageType.HANDSHAKE_REQUEST,
            payload_plaintext=card_json.encode("utf-8"),
            signing_key=agent._key_manager.signing_key,
            recipient_verify_key=recipient_vk,
        )

        return to_wire_dict(envelope)

    async def handle_inbound(
        self,
        agent: Agent,
        envelope: MessageEnvelope,
        sender_vk: VerifyKey,
    ) -> ReceivedMessage | None:
        """Handle an inbound handshake message.

        Returns None -- handshake messages are not user-visible.
        """
        if envelope.type == MessageType.HANDSHAKE_REQUEST.value:
            await self._handle_request(agent, envelope, sender_vk)
        elif envelope.type == MessageType.HANDSHAKE_ACCEPT.value:
            await self._handle_accept(agent, envelope, sender_vk)
        elif envelope.type == MessageType.HANDSHAKE_DENY.value:
            logger.warning(
                "Handshake denied by %s for message %s",
                envelope.from_address,
                envelope.message_id,
            )
        return None

    async def _handle_request(
        self,
        agent: Agent,
        envelope: MessageEnvelope,
        sender_vk: VerifyKey,
    ) -> None:
        """Process a handshake.request: decrypt contact card, apply trust policy."""
        # Handshake requests are encrypted with SealedBox (anonymous)
        plaintext = decrypt_payload_anonymous(
            envelope.payload, agent._key_manager.signing_key
        )
        card_dict = json.loads(plaintext.decode("utf-8"))
        card = contact_card_from_dict(card_dict)

        # Verify the contact card's self-signature
        verify_contact_card(card)

        # T1.1: bind the embedded card to the envelope sender BEFORE we
        # persist anything. Without this gate, an attacker can pre-position a
        # contact under SOMEONE ELSE's address by signing an envelope from
        # their own address but embedding a card claiming a victim's address
        # (and any key the attacker chooses).
        _bind_card_to_envelope(card, envelope, sender_vk)

        if self._trust_policy == "auto-accept":
            # Store the contact as provisional (TOFU: trust upgrades on accept)
            await self._contact_book.add_contact(
                address=card.address,
                public_key=card.public_key,
                display_name=card.display_name,
                trust_state="provisional",
                trust_source="auto-accepted-provisional",
            )
            # Send handshake.accept back
            await self._send_accept(agent, envelope.from_address, sender_vk)
            logger.info(
                "Auto-accepted handshake from %s", envelope.from_address
            )
        elif self._trust_policy == "allowlist-only":
            # Auto-deny: only pre-approved contacts are allowed
            await self._send_deny(agent, envelope.from_address, sender_vk)
            logger.info(
                "Handshake auto-denied (allowlist-only) from %s",
                envelope.from_address,
            )
        else:
            # approval-required: store in pending for manual review
            await self._contact_book.add_pending(
                envelope.from_address, json.dumps(card_dict)
            )
            logger.info(
                "Handshake from %s stored as pending (policy=%s)",
                envelope.from_address,
                self._trust_policy,
            )

    async def _handle_accept(
        self,
        agent: Agent,
        envelope: MessageEnvelope,
        sender_vk: VerifyKey,
    ) -> None:
        """Process a handshake.accept: gate on prior state, then store as pinned.

        Phase 43 T1.2 hardening:
          1. Prior-state gate -- only addresses we previously sent a
             ``handshake.request`` to (trust_state == ``"handshake-sent"``)
             may be promoted to ``"pinned"``. Unsolicited accepts are logged
             and dropped (NOT raised) so that attackers cannot DoS our log
             output by spamming forged accepts.
          2. Embedded-card cross-check -- if the accept payload contains a
             ``contact_card`` field, it must be bound to the envelope sender
             via :func:`_bind_card_to_envelope`. A mismatch raises
             :class:`InvalidEnvelopeError`.
        """
        # T1.2 (gate): only promote to pinned if we previously initiated a
        # handshake to this address. Drop unsolicited accepts silently (warn).
        prior_state = await self._contact_book.get_trust_state(
            envelope.from_address
        )
        if prior_state != "handshake-sent":
            logger.warning(
                "Unsolicited handshake.accept from %s (prior trust_state=%r); "
                "ignoring",
                envelope.from_address,
                prior_state,
            )
            return

        # T1.2 (cross-check embedded card, if present): the accept payload is
        # encrypted with NaCl Box; we need the recipient's signing key and the
        # sender's verify key to decrypt. Both are available via ``agent`` and
        # ``sender_vk``.
        try:
            plaintext = decrypt_payload(
                envelope.payload,
                agent._key_manager.signing_key,
                sender_vk,
            )
            payload_obj = json.loads(plaintext.decode("utf-8"))
        except Exception:
            payload_obj = None

        if isinstance(payload_obj, dict) and "contact_card" in payload_obj:
            try:
                accept_card = contact_card_from_dict(payload_obj["contact_card"])
            except Exception as exc:
                logger.warning(
                    "handshake.accept from %s carried an invalid contact_card; "
                    "ignoring: %s",
                    envelope.from_address,
                    exc,
                )
                return
            # Raises InvalidEnvelopeError on mismatch (T1.1 binding for accept)
            _bind_card_to_envelope(accept_card, envelope, sender_vk)

        sender_pk_str = serialize_verify_key(sender_vk)
        await self._contact_book.add_contact(
            address=envelope.from_address,
            public_key=sender_pk_str,
            trust_state="pinned",
        )
        await self._contact_book.set_pinned_at(envelope.from_address)
        logger.info(
            "Handshake accepted by %s, stored as pinned (TOFU)", envelope.from_address
        )

    async def _send_accept(
        self,
        agent: Agent,
        to_address: str,
        recipient_vk: VerifyKey,
    ) -> None:
        """Send a handshake.accept envelope back to the requester.

        Embeds the recipient's own contact card in the accept payload so the
        original sender can verify and store it (mirrors the request format).
        """
        card = create_contact_card(
            address=agent.address,
            display_name=agent._config.display_name,
            relay=agent._config.relay_ws_url,
            signing_key=agent._key_manager.signing_key,
        )
        accept_payload = json.dumps({
            "status": "accepted",
            "contact_card": contact_card_to_dict(card),
        }).encode("utf-8")

        envelope = create_envelope(
            from_address=agent.address,
            to_address=to_address,
            message_type=MessageType.HANDSHAKE_ACCEPT,
            payload_plaintext=accept_payload,
            signing_key=agent._key_manager.signing_key,
            recipient_verify_key=recipient_vk,
        )

        wire = to_wire_dict(envelope)
        await agent._transport.send(wire)

    async def _send_deny(
        self,
        agent: Agent,
        to_address: str,
        recipient_vk: VerifyKey,
    ) -> None:
        """Send a handshake.deny envelope to the requester."""
        deny_payload = json.dumps({
            "status": "denied",
            "reason": "allowlist-only",
        }).encode("utf-8")

        envelope = create_envelope(
            from_address=agent.address,
            to_address=to_address,
            message_type=MessageType.HANDSHAKE_DENY,
            payload_plaintext=deny_payload,
            signing_key=agent._key_manager.signing_key,
            recipient_verify_key=recipient_vk,
        )

        wire = to_wire_dict(envelope)
        await agent._transport.send(wire)

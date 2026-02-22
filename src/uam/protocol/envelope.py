"""UAM message envelope -- creation, signing, verification, wire format.

An envelope wraps every UAM message with cryptographic signatures and
encrypted payloads, using the ``from_address`` / ``to_address`` naming
convention internally (``from`` / ``to`` on the wire).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Optional

import uuid6

from uam.protocol.address import parse_address
from uam.protocol.crypto import (
    canonicalize,
    encrypt_payload,
    encrypt_payload_anonymous,
    generate_nonce,
    sign_message,
    verify_signature,
)
from uam.protocol.errors import EnvelopeTooLargeError, InvalidEnvelopeError
from uam.protocol.types import MAX_ENVELOPE_SIZE, UAM_VERSION, MessageType, utc_timestamp

from nacl.signing import SigningKey, VerifyKey


# Required wire-format field names (using ``from`` / ``to``)
_REQUIRED_WIRE_FIELDS = frozenset(
    ["uam_version", "message_id", "from", "to", "timestamp", "type", "nonce", "payload", "signature"]
)


@dataclass(frozen=True)
class MessageEnvelope:
    """A signed, encrypted UAM message envelope.

    Python attribute names use ``from_address`` / ``to_address``
    because ``from`` is a reserved keyword.
    """

    # Required fields
    uam_version: str
    message_id: str
    from_address: str
    to_address: str
    timestamp: str
    type: str
    nonce: str
    payload: str
    signature: str

    # Optional fields
    thread_id: Optional[str] = None
    reply_to: Optional[str] = None
    expires: Optional[str] = None
    media_type: Optional[str] = None
    metadata: Optional[dict] = None

    # v1.1 fields -- NOT in signature scope (backward compat with v1.0 agents)
    attachments: Optional[list[dict]] = None


def _build_signable_dict(envelope: MessageEnvelope) -> dict:
    """Build the dict used for signature computation.

    Maps Python names to wire names (``from_address`` -> ``from``).
    Excludes ``signature`` and any optional field that is ``None``.
    """
    d: dict = {
        "uam_version": envelope.uam_version,
        "message_id": envelope.message_id,
        "from": envelope.from_address,
        "to": envelope.to_address,
        "timestamp": envelope.timestamp,
        "type": envelope.type,
        "nonce": envelope.nonce,
        "payload": envelope.payload,
    }
    # Add non-None optional fields
    if envelope.thread_id is not None:
        d["thread_id"] = envelope.thread_id
    if envelope.reply_to is not None:
        d["reply_to"] = envelope.reply_to
    if envelope.expires is not None:
        d["expires"] = envelope.expires
    if envelope.media_type is not None:
        d["media_type"] = envelope.media_type
    if envelope.metadata is not None:
        d["metadata"] = envelope.metadata
    return d


def to_wire_dict(envelope: MessageEnvelope) -> dict:
    """Convert an envelope to a wire-format dict.

    Maps ``from_address`` -> ``"from"`` and ``to_address`` -> ``"to"``.
    Excludes ``None``-valued optional fields.
    """
    d = _build_signable_dict(envelope)
    d["signature"] = envelope.signature
    if envelope.attachments is not None:
        d["attachments"] = envelope.attachments
    return d


def from_wire_dict(d: dict) -> MessageEnvelope:
    """Restore an envelope from a wire-format dict.

    Raises:
        InvalidEnvelopeError: If any required field is missing.
    """
    missing = _REQUIRED_WIRE_FIELDS - set(d.keys())
    if missing:
        raise InvalidEnvelopeError(f"Missing required fields: {sorted(missing)}")

    return MessageEnvelope(
        uam_version=d["uam_version"],
        message_id=d["message_id"],
        from_address=d["from"],
        to_address=d["to"],
        timestamp=d["timestamp"],
        type=d["type"],
        nonce=d["nonce"],
        payload=d["payload"],
        signature=d["signature"],
        thread_id=d.get("thread_id"),
        reply_to=d.get("reply_to"),
        expires=d.get("expires"),
        media_type=d.get("media_type"),
        metadata=d.get("metadata"),
        attachments=d.get("attachments"),
    )


def validate_envelope_size(envelope: MessageEnvelope) -> None:
    """Check that the serialized envelope does not exceed MAX_ENVELOPE_SIZE.

    Raises:
        EnvelopeTooLargeError: If the wire JSON exceeds 64 KB.
    """
    wire = to_wire_dict(envelope)
    size = len(json.dumps(wire, separators=(",", ":"), ensure_ascii=True).encode("utf-8"))
    if size > MAX_ENVELOPE_SIZE:
        raise EnvelopeTooLargeError(
            f"Envelope size {size} bytes exceeds maximum {MAX_ENVELOPE_SIZE} bytes"
        )


def create_envelope(
    from_address: str,
    to_address: str,
    message_type: MessageType | str,
    payload_plaintext: bytes,
    signing_key: SigningKey,
    recipient_verify_key: VerifyKey,
    *,
    thread_id: str | None = None,
    reply_to: str | None = None,
    expires: str | None = None,
    media_type: str | None = None,
    metadata: dict | None = None,
    attachments: list[dict] | None = None,
) -> MessageEnvelope:
    """Create a signed, encrypted message envelope.

    *message_type* may be a :class:`MessageType` enum member or a plain
    string (e.g. ``"message"``).  Strings are normalised to enum values
    internally so that SealedBox routing and wire format work correctly.

    Steps:
        1. Validate addresses
        2. Generate message_id (UUIDv7), nonce, timestamp
        3. Encrypt payload (SealedBox for handshake.request, NaCl Box otherwise)
        4. Build signable dict and sign with canonicalize
        5. Validate envelope size
        6. Return frozen envelope

    Raises:
        InvalidAddressError: If either address is invalid.
        EnvelopeTooLargeError: If the serialized envelope exceeds 64 KB.
    """
    # Normalise message_type to enum so comparisons are reliable
    if isinstance(message_type, str):
        message_type = MessageType(message_type)

    # Step 1: Validate addresses
    parse_address(from_address)
    parse_address(to_address)

    # Step 2: Generate identifiers
    message_id = str(uuid6.uuid7())
    nonce = generate_nonce()
    timestamp = utc_timestamp()

    # Step 3: Encrypt payload
    # Handshake requests use SealedBox (anonymous encryption) because the
    # sender may not have an established relationship with the recipient yet.
    # All other message types use NaCl Box (authenticated encryption).
    if message_type == MessageType.HANDSHAKE_REQUEST:
        encrypted_payload = encrypt_payload_anonymous(payload_plaintext, recipient_verify_key)
    else:
        encrypted_payload = encrypt_payload(payload_plaintext, signing_key, recipient_verify_key)

    type_value = message_type.value

    # Build a temporary envelope without signature to compute signable dict
    temp_envelope = MessageEnvelope(
        uam_version=UAM_VERSION,
        message_id=message_id,
        from_address=from_address,
        to_address=to_address,
        timestamp=timestamp,
        type=type_value,
        nonce=nonce,
        payload=encrypted_payload,
        signature="",  # placeholder
        thread_id=thread_id,
        reply_to=reply_to,
        expires=expires,
        media_type=media_type,
        metadata=metadata,
        attachments=attachments,
    )

    # Step 4: Build signable dict, canonicalize, and sign
    signable = _build_signable_dict(temp_envelope)
    signature = sign_message(canonicalize(signable), signing_key)

    # Step 5: Build final envelope with real signature
    final_envelope = MessageEnvelope(
        uam_version=UAM_VERSION,
        message_id=message_id,
        from_address=from_address,
        to_address=to_address,
        timestamp=timestamp,
        type=type_value,
        nonce=nonce,
        payload=encrypted_payload,
        signature=signature,
        thread_id=thread_id,
        reply_to=reply_to,
        expires=expires,
        media_type=media_type,
        metadata=metadata,
        attachments=attachments,
    )

    # Step 6: Validate size before returning
    validate_envelope_size(final_envelope)

    return final_envelope


def verify_envelope(envelope: MessageEnvelope, sender_verify_key: VerifyKey) -> None:
    """Verify the cryptographic signature on an envelope.

    Uses the same ``_build_signable_dict`` helper as ``create_envelope``
    to ensure signature scope consistency.

    Raises:
        SignatureVerificationError: If the signature is invalid.
    """
    signable = _build_signable_dict(envelope)
    verify_signature(canonicalize(signable), envelope.signature, sender_verify_key)

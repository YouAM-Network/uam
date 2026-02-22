"""UAM Protocol -- Universal Agent Messaging protocol library.

Public API re-exports for ``uam.protocol``.
"""

from uam.protocol.types import (
    UAM_VERSION,
    MAX_ENVELOPE_SIZE,
    MessageType,
    b64_encode,
    b64_decode,
    utc_timestamp,
)

from uam.protocol.errors import (
    UAMError,
    InvalidAddressError,
    InvalidEnvelopeError,
    EnvelopeTooLargeError,
    SignatureError,
    SignatureVerificationError,
    EncryptionError,
    DecryptionError,
    InvalidContactCardError,
)

from uam.protocol.address import Address, parse_address

from uam.protocol.crypto import (
    generate_keypair,
    serialize_signing_key,
    deserialize_signing_key,
    serialize_verify_key,
    deserialize_verify_key,
    public_key_fingerprint,
    canonicalize,
    sign_message,
    verify_signature,
    generate_nonce,
    encrypt_payload,
    decrypt_payload,
    encrypt_payload_anonymous,
    decrypt_payload_anonymous,
)

from uam.protocol.envelope import (
    MessageEnvelope,
    create_envelope,
    verify_envelope,
    to_wire_dict,
    from_wire_dict,
    validate_envelope_size,
)

from uam.protocol.contact import (
    ContactCard,
    create_contact_card,
    verify_contact_card,
    contact_card_to_dict,
    contact_card_from_dict,
)

__all__ = [
    # Types
    "UAM_VERSION",
    "MAX_ENVELOPE_SIZE",
    "MessageType",
    "b64_encode",
    "b64_decode",
    "utc_timestamp",
    # Errors
    "UAMError",
    "InvalidAddressError",
    "InvalidEnvelopeError",
    "EnvelopeTooLargeError",
    "SignatureError",
    "SignatureVerificationError",
    "EncryptionError",
    "DecryptionError",
    "InvalidContactCardError",
    # Address
    "Address",
    "parse_address",
    # Crypto
    "generate_keypair",
    "serialize_signing_key",
    "deserialize_signing_key",
    "serialize_verify_key",
    "deserialize_verify_key",
    "public_key_fingerprint",
    "canonicalize",
    "sign_message",
    "verify_signature",
    "generate_nonce",
    "encrypt_payload",
    "decrypt_payload",
    "encrypt_payload_anonymous",
    "decrypt_payload_anonymous",
    # Envelope
    "MessageEnvelope",
    "create_envelope",
    "verify_envelope",
    "to_wire_dict",
    "from_wire_dict",
    "validate_envelope_size",
    # Contact
    "ContactCard",
    "create_contact_card",
    "verify_contact_card",
    "contact_card_to_dict",
    "contact_card_from_dict",
]

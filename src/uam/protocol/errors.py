"""UAM exception hierarchy.

All protocol-specific exceptions inherit from :class:`UAMError`.
"""

from __future__ import annotations


class UAMError(Exception):
    """Base exception for all UAM protocol errors."""


class InvalidAddressError(UAMError):
    """Raised when an address string fails validation."""


class InvalidEnvelopeError(UAMError):
    """Raised when an envelope fails schema validation."""


class EnvelopeTooLargeError(InvalidEnvelopeError):
    """Raised when an envelope exceeds the maximum allowed size."""


class SignatureError(UAMError):
    """Raised on signing failures."""


class SignatureVerificationError(SignatureError):
    """Raised when a cryptographic signature cannot be verified."""


class EncryptionError(UAMError):
    """Raised on encryption failures."""


class DecryptionError(EncryptionError):
    """Raised on decryption failures."""


class InvalidContactCardError(UAMError):
    """Raised when a contact card fails validation."""


class KeyPinningError(UAMError):
    """Raised when a pinned contact's public key doesn't match the resolved key."""


# ===========================================================================
# Phase 48 (Q1) — Extended hierarchy with stdlib mixins.
# Strictly additive: existing `except ValueError` callers continue to work.
# ===========================================================================


class ProtocolError(UAMError):
    """Wire-protocol violations (envelope shape, version, signature)."""


class ValidationError(ProtocolError, ValueError):
    """User-supplied data fails validation.

    Inherits ValueError so existing ``except ValueError`` callers continue
    to catch the new typed exception (mixin pattern, MRO-safe).
    """


class IncompatibleVersionError(ProtocolError):
    """Envelope or wire payload uses an unsupported MAJOR version.

    Args:
        version: The version string seen on the wire (e.g. ``"99.0"``).
        supported: Tuple of supported MAJOR version strings (e.g. ``("0",)``).
    """

    def __init__(self, version: str, supported: tuple[str, ...]) -> None:
        super().__init__(
            f"unsupported uam_version {version!r}; supported: {supported}"
        )
        self.version = version
        self.supported = supported


class ContactCardExpired(ValidationError):
    """ContactCard.not_after has passed.

    Args:
        address: The address string of the expired card.
        expired_at: ISO-8601 timestamp marking expiry.
    """

    def __init__(self, address: str, expired_at: str) -> None:
        super().__init__(
            f"contact card for {address} expired at {expired_at}"
        )
        self.address = address
        self.expired_at = expired_at


class EnvelopeExpiredError(ProtocolError):
    """Envelope.expires has passed (Phase 45 hook; this plan adds the type)."""


class ReplayDetected(ProtocolError):
    """Inbound message matches a known nonce / message_id (Phase 45 hook)."""


class UnknownFieldError(ProtocolError):
    """Strict-parsed wire dict contains an unknown field.

    Forward-compat: callers who want lenient parsing should catch this and
    treat unknown fields as opaque pass-through.
    """

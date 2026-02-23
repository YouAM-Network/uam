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

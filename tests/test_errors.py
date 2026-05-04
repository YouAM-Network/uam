"""Tests for uam.protocol.errors module."""

from __future__ import annotations

import pytest

from uam.protocol.errors import (
    UAMError,
    InvalidAddressError,
    InvalidEnvelopeError,
    SignatureError,
    SignatureVerificationError,
    EncryptionError,
    DecryptionError,
    InvalidContactCardError,
)


class TestHierarchy:
    def test_invalid_address_is_uam_error(self):
        assert issubclass(InvalidAddressError, UAMError)

    def test_invalid_envelope_is_uam_error(self):
        assert issubclass(InvalidEnvelopeError, UAMError)

    def test_signature_error_is_uam_error(self):
        assert issubclass(SignatureError, UAMError)

    def test_signature_verification_is_signature_error(self):
        assert issubclass(SignatureVerificationError, SignatureError)

    def test_encryption_error_is_uam_error(self):
        assert issubclass(EncryptionError, UAMError)

    def test_decryption_is_encryption_error(self):
        assert issubclass(DecryptionError, EncryptionError)

    def test_invalid_contact_card_is_uam_error(self):
        assert issubclass(InvalidContactCardError, UAMError)


class TestMessages:
    def test_uam_error_message(self):
        err = UAMError("something broke")
        assert str(err) == "something broke"

    def test_invalid_address_message(self):
        err = InvalidAddressError("bad address")
        assert str(err) == "bad address"

    def test_signature_verification_message(self):
        err = SignatureVerificationError("bad sig")
        assert str(err) == "bad sig"

    def test_decryption_error_message(self):
        err = DecryptionError("cannot decrypt")
        assert str(err) == "cannot decrypt"

    def test_no_message(self):
        err = UAMError()
        assert str(err) == ""


class TestCatchability:
    def test_catch_invalid_address_as_uam_error(self):
        with pytest.raises(UAMError):
            raise InvalidAddressError("test")

    def test_catch_signature_verification_as_signature_error(self):
        with pytest.raises(SignatureError):
            raise SignatureVerificationError("test")

    def test_catch_decryption_as_encryption_error(self):
        with pytest.raises(EncryptionError):
            raise DecryptionError("test")


# ===========================================================================
# Q1 — UAMError hierarchy mixin-inheritance contract tests (Phase 48 Wave 0)
#
# These tests are RED on purpose: they assert against Wave 1 (48-01) contracts
# (ValidationError, ProtocolError, IncompatibleVersionError, ContactCardExpired,
# EnvelopeExpiredError, ReplayDetected, UnknownFieldError) that do not exist
# yet on this branch. Wave 1 will add the new exceptions WITH ValueError /
# ProtocolError mixins so existing `except ValueError` callers still catch.
# ===========================================================================

# Imports placed inside tests so the file is collectable on main even though
# the new symbols don't exist yet — each test fails at import-time with a
# specific ImportError (the intended Wave 0 red signal).


def test_validation_error_caught_by_value_error():
    """Existing `except ValueError` callers MUST still catch new ValidationError."""
    from uam.protocol.errors import ValidationError  # NEW in Wave 1
    with pytest.raises(ValueError):
        raise ValidationError("test")


def test_validation_error_caught_by_uam_error():
    from uam.protocol.errors import ValidationError
    with pytest.raises(UAMError):
        raise ValidationError("test")


def test_validation_error_caught_by_protocol_error():
    from uam.protocol.errors import ValidationError, ProtocolError
    with pytest.raises(ProtocolError):
        raise ValidationError("test")


# --- Backward-compat: every existing error must STILL be catchable by old name ---

@pytest.mark.parametrize("exc_cls_name", [
    "InvalidAddressError",
    "InvalidEnvelopeError",
    "EnvelopeTooLargeError",
    "SignatureError",
    "SignatureVerificationError",
    "EncryptionError",
    "DecryptionError",
    "InvalidContactCardError",
    "KeyPinningError",
])
def test_existing_errors_still_catchable_as_uam_error(exc_cls_name):
    """Every Phase 43-47 typed error stays catchable by `except UAMError`."""
    import uam.protocol.errors as errors_mod
    exc_cls = getattr(errors_mod, exc_cls_name)
    with pytest.raises(UAMError):
        raise exc_cls("test")


# --- New typed exceptions (Q1) ---

def test_incompatible_version_error_carries_version_and_supported():
    from uam.protocol.errors import IncompatibleVersionError  # NEW in Wave 1
    exc = IncompatibleVersionError("99.0", ("0",))
    assert exc.version == "99.0"
    assert exc.supported == ("0",)
    assert "99.0" in str(exc)


def test_contact_card_expired_carries_address_and_expired_at():
    from uam.protocol.errors import ContactCardExpired  # NEW in Wave 1
    exc = ContactCardExpired("alice::test", "2020-01-01T00:00:00Z")
    assert exc.address == "alice::test"
    assert exc.expired_at == "2020-01-01T00:00:00Z"


def test_envelope_expired_error_inherits_protocol_error():
    from uam.protocol.errors import EnvelopeExpiredError, ProtocolError
    assert issubclass(EnvelopeExpiredError, ProtocolError)


def test_replay_detected_inherits_protocol_error():
    from uam.protocol.errors import ReplayDetected, ProtocolError
    assert issubclass(ReplayDetected, ProtocolError)


def test_unknown_field_error_inherits_protocol_error():
    from uam.protocol.errors import UnknownFieldError, ProtocolError
    assert issubclass(UnknownFieldError, ProtocolError)

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

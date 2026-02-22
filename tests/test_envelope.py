"""Tests for uam.protocol.envelope module."""

from __future__ import annotations

import dataclasses
import re
import uuid

import pytest

from uam.protocol.crypto import decrypt_payload, decrypt_payload_anonymous, generate_keypair
from uam.protocol.envelope import (
    MessageEnvelope,
    create_envelope,
    from_wire_dict,
    to_wire_dict,
    validate_envelope_size,
    verify_envelope,
)
from uam.protocol.envelope import _build_signable_dict
from uam.protocol.errors import (
    EnvelopeTooLargeError,
    InvalidAddressError,
    InvalidEnvelopeError,
    SignatureVerificationError,
)
from uam.protocol.types import MessageType, b64_decode


# ---------------------------------------------------------------------------
# v1.0 regression -- locks current wire format before any v1.1 changes
# ---------------------------------------------------------------------------

class TestV10Regression:
    """Lock down v1.0 wire format so v1.1 additions don't silently break it."""

    def test_v10_envelope_signature_still_valid(self, keypair_pair):
        """v1.0 envelope (no attachments) must verify before AND after wire round-trip."""
        (alice_sk, alice_vk), (_, bob_vk) = keypair_pair
        env = create_envelope(
            from_address="alice::youam.network",
            to_address="bob::youam.network",
            message_type=MessageType.MESSAGE,
            payload_plaintext=b"v1.0 regression payload",
            signing_key=alice_sk,
            recipient_verify_key=bob_vk,
        )
        # Verify signature on freshly created envelope
        verify_envelope(env, alice_vk)

        # Round-trip through wire format
        wire = to_wire_dict(env)
        restored = from_wire_dict(wire)

        # Verify signature on restored envelope
        verify_envelope(restored, alice_vk)

    def test_v10_wire_dict_keys(self, keypair_pair):
        """v1.0 envelope with no optional fields must produce exactly the required keys."""
        (alice_sk, _), (_, bob_vk) = keypair_pair
        env = create_envelope(
            from_address="alice::youam.network",
            to_address="bob::youam.network",
            message_type=MessageType.MESSAGE,
            payload_plaintext=b"hello",
            signing_key=alice_sk,
            recipient_verify_key=bob_vk,
        )
        wire = to_wire_dict(env)
        expected_keys = {
            "uam_version", "message_id", "from", "to",
            "timestamp", "type", "nonce", "payload", "signature",
        }
        assert set(wire.keys()) == expected_keys


# ---------------------------------------------------------------------------
# Creation and required fields
# ---------------------------------------------------------------------------

class TestCreation:
    def test_all_required_fields_present(self, keypair_pair):
        (alice_sk, _), (_, bob_vk) = keypair_pair
        env = create_envelope(
            from_address="alice::youam.network",
            to_address="bob::youam.network",
            message_type=MessageType.MESSAGE,
            payload_plaintext=b"hello",
            signing_key=alice_sk,
            recipient_verify_key=bob_vk,
        )
        assert env.uam_version is not None
        assert env.message_id is not None
        assert env.from_address is not None
        assert env.to_address is not None
        assert env.timestamp is not None
        assert env.type is not None
        assert env.nonce is not None
        assert env.payload is not None
        assert env.signature is not None

    def test_message_id_is_valid_uuid(self, keypair_pair):
        (alice_sk, _), (_, bob_vk) = keypair_pair
        env = create_envelope(
            from_address="alice::youam.network",
            to_address="bob::youam.network",
            message_type=MessageType.MESSAGE,
            payload_plaintext=b"hello",
            signing_key=alice_sk,
            recipient_verify_key=bob_vk,
        )
        # Should parse as a valid UUID
        uuid.UUID(env.message_id)

    def test_timestamp_format(self, keypair_pair):
        (alice_sk, _), (_, bob_vk) = keypair_pair
        env = create_envelope(
            from_address="alice::youam.network",
            to_address="bob::youam.network",
            message_type=MessageType.MESSAGE,
            payload_plaintext=b"hello",
            signing_key=alice_sk,
            recipient_verify_key=bob_vk,
        )
        pattern = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$"
        assert re.match(pattern, env.timestamp)

    def test_uam_version(self, keypair_pair):
        (alice_sk, _), (_, bob_vk) = keypair_pair
        env = create_envelope(
            from_address="alice::youam.network",
            to_address="bob::youam.network",
            message_type=MessageType.MESSAGE,
            payload_plaintext=b"hello",
            signing_key=alice_sk,
            recipient_verify_key=bob_vk,
        )
        assert env.uam_version == "0.1"

    def test_type_matches_message_type(self, keypair_pair):
        (alice_sk, _), (_, bob_vk) = keypair_pair
        env = create_envelope(
            from_address="alice::youam.network",
            to_address="bob::youam.network",
            message_type=MessageType.HANDSHAKE_REQUEST,
            payload_plaintext=b"hello",
            signing_key=alice_sk,
            recipient_verify_key=bob_vk,
        )
        assert env.type == "handshake.request"

    def test_string_message_type_accepted(self, keypair_pair):
        """create_envelope accepts a plain string for message_type."""
        (alice_sk, alice_vk), (_, bob_vk) = keypair_pair
        env = create_envelope(
            from_address="alice::youam.network",
            to_address="bob::youam.network",
            message_type="message",
            payload_plaintext=b"hello",
            signing_key=alice_sk,
            recipient_verify_key=bob_vk,
        )
        assert env.type == "message"
        verify_envelope(env, alice_vk)

    def test_nonce_decodes_to_24_bytes(self, keypair_pair):
        (alice_sk, _), (_, bob_vk) = keypair_pair
        env = create_envelope(
            from_address="alice::youam.network",
            to_address="bob::youam.network",
            message_type=MessageType.MESSAGE,
            payload_plaintext=b"hello",
            signing_key=alice_sk,
            recipient_verify_key=bob_vk,
        )
        assert len(b64_decode(env.nonce)) == 24


# ---------------------------------------------------------------------------
# Wire format conversion
# ---------------------------------------------------------------------------

class TestWireFormat:
    def test_to_wire_uses_from_to_keys(self, sample_envelope):
        wire = to_wire_dict(sample_envelope)
        assert "from" in wire
        assert "to" in wire
        assert "from_address" not in wire
        assert "to_address" not in wire

    def test_from_wire_maps_correctly(self, sample_envelope):
        wire = to_wire_dict(sample_envelope)
        restored = from_wire_dict(wire)
        assert restored.from_address == sample_envelope.from_address
        assert restored.to_address == sample_envelope.to_address

    def test_roundtrip_preserves_all_fields(self, keypair_pair):
        (alice_sk, _), (_, bob_vk) = keypair_pair
        env = create_envelope(
            from_address="alice::youam.network",
            to_address="bob::youam.network",
            message_type=MessageType.MESSAGE,
            payload_plaintext=b"test",
            signing_key=alice_sk,
            recipient_verify_key=bob_vk,
            thread_id="thread-1",
            reply_to="reply-id",
            expires="2026-12-31T23:59:59.000Z",
            media_type="text/plain",
            metadata={"key": "value"},
        )
        restored = from_wire_dict(to_wire_dict(env))
        assert restored == env

    def test_from_wire_missing_required_raises(self):
        wire = {"uam_version": "0.1", "message_id": "abc"}
        with pytest.raises(InvalidEnvelopeError):
            from_wire_dict(wire)

    def test_none_optionals_excluded_from_wire(self, sample_envelope):
        wire = to_wire_dict(sample_envelope)
        assert "thread_id" not in wire
        assert "reply_to" not in wire
        assert "expires" not in wire
        assert "media_type" not in wire
        assert "metadata" not in wire


# ---------------------------------------------------------------------------
# Signing and verification
# ---------------------------------------------------------------------------

class TestSigningVerification:
    def test_verify_succeeds_on_fresh_envelope(self, keypair_pair):
        (alice_sk, alice_vk), (_, bob_vk) = keypair_pair
        env = create_envelope(
            from_address="alice::youam.network",
            to_address="bob::youam.network",
            message_type=MessageType.MESSAGE,
            payload_plaintext=b"hello",
            signing_key=alice_sk,
            recipient_verify_key=bob_vk,
        )
        verify_envelope(env, alice_vk)  # should not raise

    def test_wrong_key_raises(self, keypair_pair):
        (alice_sk, _), (_, bob_vk) = keypair_pair
        _, eve_vk = generate_keypair()
        env = create_envelope(
            from_address="alice::youam.network",
            to_address="bob::youam.network",
            message_type=MessageType.MESSAGE,
            payload_plaintext=b"hello",
            signing_key=alice_sk,
            recipient_verify_key=bob_vk,
        )
        with pytest.raises(SignatureVerificationError):
            verify_envelope(env, eve_vk)

    def test_tampered_to_address_raises(self, keypair_pair):
        (alice_sk, alice_vk), (_, bob_vk) = keypair_pair
        env = create_envelope(
            from_address="alice::youam.network",
            to_address="bob::youam.network",
            message_type=MessageType.MESSAGE,
            payload_plaintext=b"hello",
            signing_key=alice_sk,
            recipient_verify_key=bob_vk,
        )
        tampered = dataclasses.replace(env, to_address="eve::youam.network")
        with pytest.raises(SignatureVerificationError):
            verify_envelope(tampered, alice_vk)

    def test_nonce_in_signature_scope(self, keypair_pair):
        """MSG-06: Modifying nonce must break verification."""
        (alice_sk, alice_vk), (_, bob_vk) = keypair_pair
        env = create_envelope(
            from_address="alice::youam.network",
            to_address="bob::youam.network",
            message_type=MessageType.MESSAGE,
            payload_plaintext=b"hello",
            signing_key=alice_sk,
            recipient_verify_key=bob_vk,
        )
        tampered = dataclasses.replace(env, nonce="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        with pytest.raises(SignatureVerificationError):
            verify_envelope(tampered, alice_vk)


# ---------------------------------------------------------------------------
# Encryption
# ---------------------------------------------------------------------------

class TestEncryption:
    def test_recipient_can_decrypt(self, keypair_pair):
        (alice_sk, alice_vk), (bob_sk, bob_vk) = keypair_pair
        plaintext = b"secret message"
        env = create_envelope(
            from_address="alice::youam.network",
            to_address="bob::youam.network",
            message_type=MessageType.MESSAGE,
            payload_plaintext=plaintext,
            signing_key=alice_sk,
            recipient_verify_key=bob_vk,
        )
        decrypted = decrypt_payload(env.payload, bob_sk, alice_vk)
        assert decrypted == plaintext

    def test_third_party_cannot_decrypt(self, keypair_pair):
        (alice_sk, alice_vk), (_, bob_vk) = keypair_pair
        env = create_envelope(
            from_address="alice::youam.network",
            to_address="bob::youam.network",
            message_type=MessageType.MESSAGE,
            payload_plaintext=b"secret",
            signing_key=alice_sk,
            recipient_verify_key=bob_vk,
        )
        from uam.protocol.errors import DecryptionError

        eve_sk, _ = generate_keypair()
        with pytest.raises(DecryptionError):
            decrypt_payload(env.payload, eve_sk, alice_vk)

    def test_handshake_request_uses_sealedbox(self, keypair_pair):
        """Handshake requests use SealedBox (anonymous encryption)."""
        (alice_sk, _), (bob_sk, bob_vk) = keypair_pair
        plaintext = b"contact card payload"
        env = create_envelope(
            from_address="alice::youam.network",
            to_address="bob::youam.network",
            message_type=MessageType.HANDSHAKE_REQUEST,
            payload_plaintext=plaintext,
            signing_key=alice_sk,
            recipient_verify_key=bob_vk,
        )
        # SealedBox can be decrypted with only the recipient's signing key
        decrypted = decrypt_payload_anonymous(env.payload, bob_sk)
        assert decrypted == plaintext

    def test_handshake_request_not_decryptable_by_box(self, keypair_pair):
        """SealedBox ciphertext cannot be decrypted as NaCl Box."""
        (alice_sk, alice_vk), (bob_sk, bob_vk) = keypair_pair
        env = create_envelope(
            from_address="alice::youam.network",
            to_address="bob::youam.network",
            message_type=MessageType.HANDSHAKE_REQUEST,
            payload_plaintext=b"contact card",
            signing_key=alice_sk,
            recipient_verify_key=bob_vk,
        )
        from uam.protocol.errors import DecryptionError

        with pytest.raises(DecryptionError):
            decrypt_payload(env.payload, bob_sk, alice_vk)

    def test_regular_message_still_uses_box(self, keypair_pair):
        """Non-handshake messages still use NaCl Box (authenticated encryption)."""
        (alice_sk, alice_vk), (bob_sk, bob_vk) = keypair_pair
        plaintext = b"normal message"
        env = create_envelope(
            from_address="alice::youam.network",
            to_address="bob::youam.network",
            message_type=MessageType.MESSAGE,
            payload_plaintext=plaintext,
            signing_key=alice_sk,
            recipient_verify_key=bob_vk,
        )
        # NaCl Box requires both keys to decrypt
        decrypted = decrypt_payload(env.payload, bob_sk, alice_vk)
        assert decrypted == plaintext


# ---------------------------------------------------------------------------
# Optional fields
# ---------------------------------------------------------------------------

class TestOptionalFields:
    def test_optional_fields_included(self, keypair_pair):
        (alice_sk, _), (_, bob_vk) = keypair_pair
        env = create_envelope(
            from_address="alice::youam.network",
            to_address="bob::youam.network",
            message_type=MessageType.MESSAGE,
            payload_plaintext=b"hello",
            signing_key=alice_sk,
            recipient_verify_key=bob_vk,
            thread_id="thread-1",
            reply_to="reply-id",
            expires="2026-12-31T23:59:59.000Z",
            media_type="text/plain",
            metadata={"key": "value"},
        )
        assert env.thread_id == "thread-1"
        assert env.reply_to == "reply-id"
        assert env.expires == "2026-12-31T23:59:59.000Z"
        assert env.media_type == "text/plain"
        assert env.metadata == {"key": "value"}

    def test_optional_fields_in_signature_scope(self, keypair_pair):
        """Modifying thread_id after signing must break verification."""
        (alice_sk, alice_vk), (_, bob_vk) = keypair_pair
        env = create_envelope(
            from_address="alice::youam.network",
            to_address="bob::youam.network",
            message_type=MessageType.MESSAGE,
            payload_plaintext=b"hello",
            signing_key=alice_sk,
            recipient_verify_key=bob_vk,
            thread_id="original-thread",
        )
        tampered = dataclasses.replace(env, thread_id="tampered-thread")
        with pytest.raises(SignatureVerificationError):
            verify_envelope(tampered, alice_vk)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

class TestValidation:
    def test_invalid_from_address(self, keypair_pair):
        (alice_sk, _), (_, bob_vk) = keypair_pair
        with pytest.raises(InvalidAddressError):
            create_envelope(
                from_address="not-valid",
                to_address="bob::youam.network",
                message_type=MessageType.MESSAGE,
                payload_plaintext=b"hello",
                signing_key=alice_sk,
                recipient_verify_key=bob_vk,
            )

    def test_invalid_to_address(self, keypair_pair):
        (alice_sk, _), (_, bob_vk) = keypair_pair
        with pytest.raises(InvalidAddressError):
            create_envelope(
                from_address="alice::youam.network",
                to_address="not-valid",
                message_type=MessageType.MESSAGE,
                payload_plaintext=b"hello",
                signing_key=alice_sk,
                recipient_verify_key=bob_vk,
            )

    def test_bare_name_raises(self, keypair_pair):
        (alice_sk, _), (_, bob_vk) = keypair_pair
        with pytest.raises(InvalidAddressError):
            create_envelope(
                from_address="alice",
                to_address="bob::youam.network",
                message_type=MessageType.MESSAGE,
                payload_plaintext=b"hello",
                signing_key=alice_sk,
                recipient_verify_key=bob_vk,
            )

    def test_oversized_envelope_raises(self, keypair_pair):
        """Oversized envelope raises EnvelopeTooLargeError which is also InvalidEnvelopeError."""
        (alice_sk, _), (_, bob_vk) = keypair_pair
        large_metadata = {"data": "x" * 100000}
        with pytest.raises(EnvelopeTooLargeError, match="exceeds maximum") as exc_info:
            create_envelope(
                from_address="alice::youam.network",
                to_address="bob::youam.network",
                message_type=MessageType.MESSAGE,
                payload_plaintext=b"hello",
                signing_key=alice_sk,
                recipient_verify_key=bob_vk,
                metadata=large_metadata,
            )
        # Backward compat: EnvelopeTooLargeError IS an InvalidEnvelopeError
        assert isinstance(exc_info.value, InvalidEnvelopeError)

    def test_create_envelope_raises_on_oversized(self, keypair_pair):
        """create_envelope() raises EnvelopeTooLargeError directly (no separate validate call)."""
        (alice_sk, _), (_, bob_vk) = keypair_pair
        with pytest.raises(EnvelopeTooLargeError):
            create_envelope(
                from_address="alice::youam.network",
                to_address="bob::youam.network",
                message_type=MessageType.MESSAGE,
                payload_plaintext=b"hello",
                signing_key=alice_sk,
                recipient_verify_key=bob_vk,
                metadata={"data": "x" * 100000},
            )

    def test_create_envelope_normal_size_succeeds(self, keypair_pair):
        """Normal-sized envelopes pass size validation in create_envelope()."""
        (alice_sk, _), (_, bob_vk) = keypair_pair
        env = create_envelope(
            from_address="alice::youam.network",
            to_address="bob::youam.network",
            message_type=MessageType.MESSAGE,
            payload_plaintext=b"hello",
            signing_key=alice_sk,
            recipient_verify_key=bob_vk,
        )
        assert env is not None


# ---------------------------------------------------------------------------
# Attachments (v1.1)
# ---------------------------------------------------------------------------

class TestAttachments:
    def test_attachments_default_none(self, keypair_pair):
        """Envelope created without attachments has attachments=None."""
        (alice_sk, _), (_, bob_vk) = keypair_pair
        env = create_envelope(
            from_address="alice::youam.network",
            to_address="bob::youam.network",
            message_type=MessageType.MESSAGE,
            payload_plaintext=b"hello",
            signing_key=alice_sk,
            recipient_verify_key=bob_vk,
        )
        assert env.attachments is None

    def test_attachments_roundtrip(self, keypair_pair):
        """Attachments round-trip through to_wire_dict/from_wire_dict."""
        (alice_sk, _), (_, bob_vk) = keypair_pair
        attachments = [
            {
                "filename": "doc.pdf",
                "media_type": "application/pdf",
                "size": 1024,
                "content_hash": "sha256:abc123",
                "url": "https://cdn.example.com/doc.pdf",
            }
        ]
        env = create_envelope(
            from_address="alice::youam.network",
            to_address="bob::youam.network",
            message_type=MessageType.MESSAGE,
            payload_plaintext=b"see attached",
            signing_key=alice_sk,
            recipient_verify_key=bob_vk,
            attachments=attachments,
        )
        wire = to_wire_dict(env)
        assert wire["attachments"] == attachments

        restored = from_wire_dict(wire)
        assert restored.attachments == env.attachments

    def test_attachments_excluded_from_signature_scope(self, keypair_pair):
        """Attachments must NOT appear in signable dict -- v1.0 compat."""
        (alice_sk, alice_vk), (_, bob_vk) = keypair_pair

        attachments = [{"filename": "test.txt", "size": 100}]

        env_with = create_envelope(
            from_address="alice::youam.network",
            to_address="bob::youam.network",
            message_type=MessageType.MESSAGE,
            payload_plaintext=b"hello",
            signing_key=alice_sk,
            recipient_verify_key=bob_vk,
            attachments=attachments,
        )

        env_without = create_envelope(
            from_address="alice::youam.network",
            to_address="bob::youam.network",
            message_type=MessageType.MESSAGE,
            payload_plaintext=b"hello",
            signing_key=alice_sk,
            recipient_verify_key=bob_vk,
        )

        # Both envelopes must pass signature verification
        verify_envelope(env_with, alice_vk)
        verify_envelope(env_without, alice_vk)

        # Signable dict must NOT contain "attachments"
        signable_with = _build_signable_dict(env_with)
        signable_without = _build_signable_dict(env_without)
        assert "attachments" not in signable_with
        assert "attachments" not in signable_without

    def test_attachments_not_in_wire_when_none(self, keypair_pair):
        """Wire dict must NOT contain 'attachments' key when attachments is None."""
        (alice_sk, _), (_, bob_vk) = keypair_pair
        env = create_envelope(
            from_address="alice::youam.network",
            to_address="bob::youam.network",
            message_type=MessageType.MESSAGE,
            payload_plaintext=b"hello",
            signing_key=alice_sk,
            recipient_verify_key=bob_vk,
        )
        wire = to_wire_dict(env)
        assert "attachments" not in wire

    def test_multiple_attachments(self, keypair_pair):
        """Multiple attachments round-trip correctly."""
        (alice_sk, _), (_, bob_vk) = keypair_pair
        attachments = [
            {"filename": "a.pdf", "media_type": "application/pdf", "size": 1024, "content_hash": "sha256:aaa", "url": "https://cdn.example.com/a.pdf"},
            {"filename": "b.png", "media_type": "image/png", "size": 2048, "content_hash": "sha256:bbb", "url": "https://cdn.example.com/b.png"},
            {"filename": "c.txt", "media_type": "text/plain", "size": 512, "content_hash": "sha256:ccc", "url": "https://cdn.example.com/c.txt"},
        ]
        env = create_envelope(
            from_address="alice::youam.network",
            to_address="bob::youam.network",
            message_type=MessageType.MESSAGE,
            payload_plaintext=b"multiple files",
            signing_key=alice_sk,
            recipient_verify_key=bob_vk,
            attachments=attachments,
        )
        wire = to_wire_dict(env)
        assert len(wire["attachments"]) == 3

        restored = from_wire_dict(wire)
        assert restored.attachments == attachments


# ---------------------------------------------------------------------------
# Immutability
# ---------------------------------------------------------------------------

class TestImmutability:
    def test_envelope_is_frozen(self, sample_envelope):
        with pytest.raises(AttributeError):
            sample_envelope.from_address = "eve::youam.network"  # type: ignore[misc]

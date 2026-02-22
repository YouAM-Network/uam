"""Tests for uam.protocol.crypto module."""

from __future__ import annotations

import pytest
from nacl.signing import SigningKey, VerifyKey

from uam.protocol.crypto import (
    canonicalize,
    decrypt_payload,
    decrypt_payload_anonymous,
    deserialize_signing_key,
    deserialize_verify_key,
    encrypt_payload,
    encrypt_payload_anonymous,
    generate_keypair,
    generate_nonce,
    public_key_fingerprint,
    serialize_signing_key,
    serialize_verify_key,
    sign_message,
    verify_signature,
)
from uam.protocol.errors import DecryptionError, SignatureVerificationError
from uam.protocol.types import b64_decode


# ---------------------------------------------------------------------------
# Key generation and serialization
# ---------------------------------------------------------------------------

class TestKeyGeneration:
    def test_returns_signing_and_verify_key(self):
        sk, vk = generate_keypair()
        assert isinstance(sk, SigningKey)
        assert isinstance(vk, VerifyKey)

    def test_keypairs_are_unique(self):
        sk1, vk1 = generate_keypair()
        sk2, vk2 = generate_keypair()
        assert sk1.encode() != sk2.encode()
        assert vk1.encode() != vk2.encode()

    def test_verify_key_matches_signing_key(self):
        sk, vk = generate_keypair()
        assert vk.encode() == sk.verify_key.encode()


class TestKeySerialization:
    def test_signing_key_roundtrip(self):
        sk, _ = generate_keypair()
        restored = deserialize_signing_key(serialize_signing_key(sk))
        assert restored.encode() == sk.encode()

    def test_verify_key_roundtrip(self):
        _, vk = generate_keypair()
        restored = deserialize_verify_key(serialize_verify_key(vk))
        assert restored.encode() == vk.encode()


class TestFingerprint:
    def test_returns_64_char_hex(self):
        _, vk = generate_keypair()
        fp = public_key_fingerprint(vk)
        assert len(fp) == 64
        assert all(c in "0123456789abcdef" for c in fp)

    def test_same_key_same_fingerprint(self):
        _, vk = generate_keypair()
        assert public_key_fingerprint(vk) == public_key_fingerprint(vk)

    def test_different_keys_different_fingerprints(self):
        _, vk1 = generate_keypair()
        _, vk2 = generate_keypair()
        assert public_key_fingerprint(vk1) != public_key_fingerprint(vk2)


# ---------------------------------------------------------------------------
# Canonical JSON
# ---------------------------------------------------------------------------

class TestCanonicalize:
    def test_deterministic(self):
        d = {"b": 1, "a": 2}
        assert canonicalize(d) == canonicalize(d)

    def test_sorted_keys(self):
        d = {"b": 1, "a": 2}
        assert canonicalize(d) == b'{"a":2,"b":1}'

    def test_excludes_signature(self):
        d = {"a": 1, "signature": "xyz"}
        assert canonicalize(d) == b'{"a":1}'

    def test_excludes_none_values(self):
        d = {"a": 1, "b": None}
        assert canonicalize(d) == b'{"a":1}'

    def test_includes_non_none_optional(self):
        d = {"a": 1, "b": "hello"}
        assert canonicalize(d) == b'{"a":1,"b":"hello"}'

    def test_non_ascii_escaped(self):
        d = {"emoji": "\u2603"}
        result = canonicalize(d)
        assert b"\\u2603" in result

    def test_nested_dicts_sorted(self):
        d = {"outer": {"b": 2, "a": 1}}
        result = canonicalize(d)
        assert result == b'{"outer":{"a":1,"b":2}}'

    def test_compact_separators(self):
        d = {"key": "value"}
        result = canonicalize(d)
        assert b" " not in result


# ---------------------------------------------------------------------------
# Signing and verification
# ---------------------------------------------------------------------------

class TestSignVerify:
    def test_roundtrip(self, keypair):
        sk, vk = keypair
        data = b"hello world"
        sig = sign_message(data, sk)
        verify_signature(data, sig, vk)  # should not raise

    def test_wrong_key_raises(self, keypair):
        sk, _ = keypair
        _, vk2 = generate_keypair()
        data = b"hello world"
        sig = sign_message(data, sk)
        with pytest.raises(SignatureVerificationError):
            verify_signature(data, sig, vk2)

    def test_tampered_data_raises(self, keypair):
        sk, vk = keypair
        data = b"hello world"
        sig = sign_message(data, sk)
        with pytest.raises(SignatureVerificationError):
            verify_signature(b"tampered", sig, vk)

    def test_tampered_signature_raises(self, keypair):
        sk, vk = keypair
        data = b"hello world"
        sig = sign_message(data, sk)
        # Flip a character in the signature
        tampered = "A" + sig[1:] if sig[0] != "A" else "B" + sig[1:]
        with pytest.raises(SignatureVerificationError):
            verify_signature(data, tampered, vk)


# ---------------------------------------------------------------------------
# Nonce generation
# ---------------------------------------------------------------------------

class TestNonce:
    def test_returns_string(self):
        nonce = generate_nonce()
        assert isinstance(nonce, str)

    def test_decodes_to_24_bytes(self):
        nonce = generate_nonce()
        raw = b64_decode(nonce)
        assert len(raw) == 24

    def test_unique(self):
        n1 = generate_nonce()
        n2 = generate_nonce()
        assert n1 != n2


# ---------------------------------------------------------------------------
# NaCl Box encryption
# ---------------------------------------------------------------------------

class TestBoxEncryption:
    def test_roundtrip(self, keypair_pair):
        (alice_sk, alice_vk), (bob_sk, bob_vk) = keypair_pair
        plaintext = b"secret message"
        ct = encrypt_payload(plaintext, alice_sk, bob_vk)
        result = decrypt_payload(ct, bob_sk, alice_vk)
        assert result == plaintext

    def test_wrong_recipient_key_raises(self, keypair_pair):
        (alice_sk, alice_vk), (bob_sk, bob_vk) = keypair_pair
        ct = encrypt_payload(b"secret", alice_sk, bob_vk)
        eve_sk, _ = generate_keypair()
        with pytest.raises(DecryptionError):
            decrypt_payload(ct, eve_sk, alice_vk)

    def test_wrong_sender_key_raises(self, keypair_pair):
        (alice_sk, alice_vk), (bob_sk, bob_vk) = keypair_pair
        ct = encrypt_payload(b"secret", alice_sk, bob_vk)
        _, eve_vk = generate_keypair()
        with pytest.raises(DecryptionError):
            decrypt_payload(ct, bob_sk, eve_vk)

    def test_ciphertext_differs_from_plaintext(self, keypair_pair):
        (alice_sk, _), (_, bob_vk) = keypair_pair
        plaintext = b"hello"
        ct = encrypt_payload(plaintext, alice_sk, bob_vk)
        assert b64_decode(ct) != plaintext

    def test_empty_plaintext(self, keypair_pair):
        (alice_sk, alice_vk), (bob_sk, bob_vk) = keypair_pair
        ct = encrypt_payload(b"", alice_sk, bob_vk)
        result = decrypt_payload(ct, bob_sk, alice_vk)
        assert result == b""


# ---------------------------------------------------------------------------
# NaCl SealedBox encryption
# ---------------------------------------------------------------------------

class TestSealedBoxEncryption:
    def test_anonymous_roundtrip(self, keypair):
        sk, vk = keypair
        plaintext = b"anonymous message"
        ct = encrypt_payload_anonymous(plaintext, vk)
        result = decrypt_payload_anonymous(ct, sk)
        assert result == plaintext

    def test_wrong_key_raises(self, keypair):
        _, vk = keypair
        ct = encrypt_payload_anonymous(b"secret", vk)
        eve_sk, _ = generate_keypair()
        with pytest.raises(DecryptionError):
            decrypt_payload_anonymous(ct, eve_sk)

    def test_sealed_differs_from_box(self, keypair_pair):
        (alice_sk, alice_vk), (_, bob_vk) = keypair_pair
        plaintext = b"same message"
        ct_box = encrypt_payload(plaintext, alice_sk, bob_vk)
        ct_sealed = encrypt_payload_anonymous(plaintext, bob_vk)
        assert ct_box != ct_sealed

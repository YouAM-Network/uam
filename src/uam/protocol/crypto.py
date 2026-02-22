"""Cryptographic primitives for UAM protocol.

Wraps PyNaCl (libsodium) for Ed25519 signing, Curve25519 key exchange,
NaCl Box (authenticated encryption), and NaCl SealedBox (anonymous encryption).

This module never hand-rolls crypto -- every operation delegates to PyNaCl.
"""

from __future__ import annotations

import hashlib
import json

import nacl.exceptions
import nacl.utils
from nacl.public import Box, SealedBox
from nacl.signing import SigningKey, VerifyKey

from uam.protocol.errors import (
    DecryptionError,
    EncryptionError,
    SignatureVerificationError,
)
from uam.protocol.types import b64_decode, b64_encode


# ---------------------------------------------------------------------------
# Key generation and serialization
# ---------------------------------------------------------------------------

def generate_keypair() -> tuple[SigningKey, VerifyKey]:
    """Generate an Ed25519 keypair.

    Returns:
        A ``(signing_key, verify_key)`` tuple.
    """
    sk = SigningKey.generate()
    return sk, sk.verify_key


def serialize_signing_key(key: SigningKey) -> str:
    """Serialize a signing key to URL-safe base64 (32-byte seed)."""
    return b64_encode(key.encode())


def deserialize_signing_key(s: str) -> SigningKey:
    """Restore a signing key from its base64-encoded seed."""
    return SigningKey(b64_decode(s))


def serialize_verify_key(key: VerifyKey) -> str:
    """Serialize a verify (public) key to URL-safe base64."""
    return b64_encode(key.encode())


def deserialize_verify_key(s: str) -> VerifyKey:
    """Restore a verify key from its base64 encoding."""
    return VerifyKey(b64_decode(s))


def public_key_fingerprint(verify_key: VerifyKey) -> str:
    """Return the SHA-256 hex digest of the verify key bytes.

    This 64-character string serves as the agent's identity fingerprint.
    """
    return hashlib.sha256(verify_key.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Canonical JSON
# ---------------------------------------------------------------------------

def canonicalize(data: dict) -> bytes:
    """Produce deterministic JSON bytes for signing.

    - Excludes the ``"signature"`` key.
    - Excludes keys whose value is ``None``.
    - Sorts keys, uses compact separators, ensures ASCII encoding.
    """
    filtered = {
        k: v for k, v in data.items()
        if k != "signature" and v is not None
    }
    return json.dumps(
        filtered, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


# ---------------------------------------------------------------------------
# Signing and verification
# ---------------------------------------------------------------------------

def sign_message(data: bytes, signing_key: SigningKey) -> str:
    """Sign *data* with the Ed25519 *signing_key*.

    Returns:
        The 64-byte signature as a URL-safe base64 string.
    """
    signed = signing_key.sign(data)
    return b64_encode(signed.signature)


def verify_signature(
    data: bytes, signature_b64: str, verify_key: VerifyKey
) -> None:
    """Verify an Ed25519 signature.

    Raises:
        SignatureVerificationError: If the signature is invalid.
    """
    try:
        sig_bytes = b64_decode(signature_b64)
        verify_key.verify(data, sig_bytes)
    except nacl.exceptions.BadSignatureError as exc:
        raise SignatureVerificationError(str(exc)) from exc


# ---------------------------------------------------------------------------
# Nonce generation
# ---------------------------------------------------------------------------

def generate_nonce() -> str:
    """Generate 24 cryptographically random bytes, returned as base64."""
    return b64_encode(nacl.utils.random(24))


# ---------------------------------------------------------------------------
# NaCl Box encryption (authenticated, both parties known)
# ---------------------------------------------------------------------------

def encrypt_payload(
    plaintext: bytes,
    sender_signing_key: SigningKey,
    recipient_verify_key: VerifyKey,
) -> str:
    """Encrypt *plaintext* using NaCl Box (authenticated encryption).

    Both parties are known; the sender signs implicitly via key exchange.

    Returns:
        Base64-encoded ciphertext.

    Raises:
        EncryptionError: On any libsodium error.
    """
    try:
        sender_private = sender_signing_key.to_curve25519_private_key()
        recipient_public = recipient_verify_key.to_curve25519_public_key()
        box = Box(sender_private, recipient_public)
        ciphertext = box.encrypt(plaintext)
        return b64_encode(ciphertext)
    except nacl.exceptions.CryptoError as exc:
        raise EncryptionError(str(exc)) from exc


def decrypt_payload(
    ciphertext_b64: str,
    recipient_signing_key: SigningKey,
    sender_verify_key: VerifyKey,
) -> bytes:
    """Decrypt NaCl Box ciphertext.

    Returns:
        The original plaintext bytes.

    Raises:
        DecryptionError: On any libsodium error (wrong keys, tampered data).
    """
    try:
        recipient_private = recipient_signing_key.to_curve25519_private_key()
        sender_public = sender_verify_key.to_curve25519_public_key()
        box = Box(recipient_private, sender_public)
        return box.decrypt(b64_decode(ciphertext_b64))
    except nacl.exceptions.CryptoError as exc:
        raise DecryptionError(str(exc)) from exc


# ---------------------------------------------------------------------------
# NaCl SealedBox encryption (anonymous sender)
#
# Used by create_envelope() for handshake.request messages where the sender
# may not have an established relationship with the recipient.  The envelope
# signature still authenticates the sender; SealedBox just means the
# encryption itself does not require the sender's private key.
# ---------------------------------------------------------------------------

def encrypt_payload_anonymous(
    plaintext: bytes, recipient_verify_key: VerifyKey
) -> str:
    """Encrypt *plaintext* using NaCl SealedBox (anonymous sender).

    Only the recipient's public key is required; no sender authentication.

    Returns:
        Base64-encoded ciphertext.
    """
    recipient_public = recipient_verify_key.to_curve25519_public_key()
    sealed = SealedBox(recipient_public)
    ciphertext = sealed.encrypt(plaintext)
    return b64_encode(ciphertext)


def decrypt_payload_anonymous(
    ciphertext_b64: str, recipient_signing_key: SigningKey
) -> bytes:
    """Decrypt NaCl SealedBox ciphertext.

    Returns:
        The original plaintext bytes.

    Raises:
        DecryptionError: On any libsodium error.
    """
    try:
        recipient_private = recipient_signing_key.to_curve25519_private_key()
        sealed = SealedBox(recipient_private)
        return sealed.decrypt(b64_decode(ciphertext_b64))
    except nacl.exceptions.CryptoError as exc:
        raise DecryptionError(str(exc)) from exc

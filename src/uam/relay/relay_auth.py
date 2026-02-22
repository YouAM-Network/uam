"""Relay Ed25519 keypair management and federation request signing/verification.

Each relay has its own Ed25519 keypair, separate from any agent's keys.
This module delegates all cryptographic operations to ``uam.protocol.crypto``
-- no hand-rolled crypto.
"""

from __future__ import annotations

import logging
from pathlib import Path

from nacl.signing import SigningKey, VerifyKey

from uam.protocol.crypto import (
    canonicalize,
    deserialize_signing_key,
    deserialize_verify_key,
    generate_keypair,
    serialize_signing_key,
    sign_message,
    verify_signature,
)
from uam.protocol.errors import SignatureVerificationError

logger = logging.getLogger(__name__)


def load_or_generate_relay_keypair(key_path: str) -> tuple[SigningKey, VerifyKey]:
    """Load relay keypair from file, or generate and persist a new one.

    If the file at *key_path* exists, the signing key is deserialized from it.
    Otherwise a fresh Ed25519 keypair is generated, the signing key is written
    to *key_path* (mode ``0o600``), and parent directories are created as
    needed.

    Returns:
        A ``(signing_key, verify_key)`` tuple.
    """
    path = Path(key_path)
    if path.exists():
        key_data = path.read_text().strip()
        sk = deserialize_signing_key(key_data)
        logger.info("Loaded relay keypair from %s", key_path)
        return sk, sk.verify_key

    sk, vk = generate_keypair()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(serialize_signing_key(sk))
    path.chmod(0o600)
    logger.info("Generated new relay keypair at %s", key_path)
    return sk, vk


def sign_federation_request(body: dict, signing_key: SigningKey) -> str:
    """Sign a federation request body with the relay's signing key.

    Canonicalizes *body* (deterministic JSON) then signs with Ed25519.

    Returns:
        The base64-encoded signature string.
    """
    canonical = canonicalize(body)
    return sign_message(canonical, signing_key)


def verify_federation_signature(
    body: dict, signature: str, verify_key_b64: str
) -> bool:
    """Verify a federation request signature.

    Deserializes the verify key from *verify_key_b64*, canonicalizes *body*,
    and verifies the Ed25519 signature.

    Returns:
        ``True`` if the signature is valid, ``False`` otherwise.
    """
    try:
        vk = deserialize_verify_key(verify_key_b64)
        canonical = canonicalize(body)
        verify_signature(canonical, signature, vk)
        return True
    except (SignatureVerificationError, Exception):
        # Catches both invalid-but-well-formed signatures (SignatureVerificationError)
        # and malformed signatures (nacl.exceptions.ValueError for wrong length, etc.)
        return False

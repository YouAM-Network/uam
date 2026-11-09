"""Relay Ed25519 keypair management and federation request signing/verification.

Each relay has its own Ed25519 keypair, separate from any agent's keys.
This module delegates all cryptographic operations to ``uam.protocol.crypto``
-- no hand-rolled crypto.
"""

from __future__ import annotations

import hashlib
import json
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


def load_relay_keypair(
    secret: str | None, key_path: str
) -> tuple[SigningKey, VerifyKey]:
    """Load the relay keypair, preferring the ``UAM_RELAY_KEY`` secret.

    With a secret (the base64 seed, from the operator's secret store) the key
    file is neither read nor written, so a rebuilt host keeps its identity.
    Without one, falls back to :func:`load_or_generate_relay_keypair`.
    """
    if secret:
        try:
            sk = deserialize_signing_key(secret.strip())
        except Exception:
            # Never include the value: it is the relay's private key.
            raise RuntimeError(
                "UAM_RELAY_KEY is not a valid relay signing key "
                "(expected the base64 Ed25519 seed)"
            ) from None
        logger.info("Loaded relay keypair from UAM_RELAY_KEY")
        return sk, sk.verify_key
    return load_or_generate_relay_keypair(key_path)


def relay_key_id(verify_key: VerifyKey) -> str:
    """Short id for a relay public key: the first 16 hex chars of its SHA-256."""
    return hashlib.sha256(verify_key.encode()).hexdigest()[:16]


def parse_key_history(raw: str | None, current_public_key: str) -> list[dict]:
    """Parse ``UAM_RELAY_KEY_HISTORY``: the relay's retired public keys.

    A JSON list of ``{"public_key", "valid_from"?, "retired_at"}`` objects.
    Each comes back with its ``key_id``. Anything malformed raises
    ``RuntimeError`` so a bad value stops boot rather than publishing a
    history verifiers would trust.
    """
    if not raw or not raw.strip():
        return []
    name = "UAM_RELAY_KEY_HISTORY"
    try:
        entries = json.loads(raw)
    except ValueError:
        raise RuntimeError(f"{name} is not valid JSON") from None
    if not isinstance(entries, list):
        raise RuntimeError(f"{name} must be a JSON list")
    history: list[dict] = []
    for i, entry in enumerate(entries):
        if not isinstance(entry, dict) or not isinstance(entry.get("public_key"), str):
            raise RuntimeError(f"{name}[{i}] needs a public_key")
        try:
            vk = deserialize_verify_key(entry["public_key"])
        except Exception:
            raise RuntimeError(f"{name}[{i}].public_key is not a valid key") from None
        if entry["public_key"] == current_public_key:
            raise RuntimeError(f"{name}[{i}] is the current key; list only retired keys")
        if any(h["public_key"] == entry["public_key"] for h in history):
            raise RuntimeError(f"{name}[{i}] lists a key more than once")
        retired_at = entry.get("retired_at")
        if not isinstance(retired_at, str) or not retired_at:
            raise RuntimeError(f"{name}[{i}] needs retired_at")
        valid_from = entry.get("valid_from")
        if valid_from is not None and not isinstance(valid_from, str):
            raise RuntimeError(f"{name}[{i}].valid_from must be a string")
        history.append({
            "key_id": relay_key_id(vk),
            "public_key": entry["public_key"],
            "valid_from": valid_from,
            "retired_at": retired_at,
        })
    return history


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

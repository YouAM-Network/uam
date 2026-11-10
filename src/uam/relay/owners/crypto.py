"""How the relay keeps owners' emails, sign-in codes and session tokens.

An email is stored twice: an HMAC (keyed by ``UAM_EMAIL_PEPPER``) to look
it up, and AES-GCM ciphertext (keyed by ``UAM_EMAIL_KEY``) to send to it.
Codes and session tokens are stored only as hashes.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_EMAIL_AAD = b"UAM-EMAIL-v1"
_ENC_PREFIX = "v1."
# One @, a dot in the domain, no spaces; length per RFC 5321.
_EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]+\.[^@\s]+$")
MAX_EMAIL_LENGTH = 254


def _b64d(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def normalise_email(email: str) -> str | None:
    """The address as stored (trimmed, lower case), or None if it isn't one."""
    cleaned = email.strip().lower()
    if len(cleaned) > MAX_EMAIL_LENGTH or not _EMAIL_RE.fullmatch(cleaned):
        return None
    return cleaned


def decode_email_key(value: str) -> bytes:
    """``UAM_EMAIL_KEY`` as 32 raw bytes; ValueError if it isn't."""
    try:
        raw = _b64d(value.strip())
    except (ValueError, TypeError) as exc:
        raise ValueError("not base64url") from exc
    if len(raw) != 32:
        raise ValueError("must decode to 32 bytes")
    return raw


class EmailVault:
    """Email lookup, encryption, and code hashing for one relay."""

    def __init__(self, pepper: str, key: str) -> None:
        self._pepper = pepper.encode()
        self._aead = AESGCM(decode_email_key(key))

    def lookup(self, email: str) -> str:
        """The HMAC an email is found by (normalise it first if you can)."""
        cleaned = email.strip().lower()
        return hmac.new(self._pepper, b"email\n" + cleaned.encode(), hashlib.sha256).hexdigest()

    def encrypt(self, email: str) -> str:
        nonce = os.urandom(12)
        return _ENC_PREFIX + _b64e(nonce + self._aead.encrypt(nonce, email.encode(), _EMAIL_AAD))

    def decrypt(self, stored: str) -> str:
        if not stored.startswith(_ENC_PREFIX):
            raise ValueError("unknown email ciphertext version")
        raw = _b64d(stored[len(_ENC_PREFIX):])
        return self._aead.decrypt(raw[:12], raw[12:], _EMAIL_AAD).decode()

    def user_handle(self, owner_pk: int) -> str:
        """The WebAuthn user.id for an owner: stable, opaque, 16 bytes."""
        digest = hmac.new(self._pepper, f"user\n{owner_pk}".encode(), hashlib.sha256).digest()
        return _b64e(digest[:16])

    def code_hash(self, email_hmac: str, code: str) -> str:
        """A sign-in code's hash, bound to the email it was sent to."""
        msg = f"code\n{email_hmac}\n{code}".encode()
        return hmac.new(self._pepper, msg, hashlib.sha256).hexdigest()

    def link_code_hash(self, code: str) -> str:
        """A setup or link code's hash (the code normalised: 8 characters)."""
        return hmac.new(self._pepper, f"link-code\n{code}".encode(), hashlib.sha256).hexdigest()


#: Link codes: no 0/O, 1/I/L or U, so a code read aloud or retyped survives.
LINK_CODE_ALPHABET = "ABCDEFGHJKMNPQRSTVWXYZ23456789"
LINK_CODE_LENGTH = 8


def new_link_code() -> str:
    """Eight characters (about 39 bits); shown as ``ABCD-EFGH``."""
    return "".join(secrets.choice(LINK_CODE_ALPHABET) for _ in range(LINK_CODE_LENGTH))


def normalise_link_code(text: str) -> str | None:
    """A typed code without case, spaces or dashes, or None if it can't be one."""
    cleaned = re.sub(r"[\s-]", "", text).upper()
    if len(cleaned) != LINK_CODE_LENGTH or any(c not in LINK_CODE_ALPHABET for c in cleaned):
        return None
    return cleaned


def new_code() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"


def new_token() -> str:
    return secrets.token_urlsafe(32)


def token_hash(token: str) -> str:
    """Session tokens carry 256 random bits, so a plain SHA-256 is enough."""
    return hashlib.sha256(b"UAM-OWNER-SESSION-v1\n" + token.encode()).hexdigest()

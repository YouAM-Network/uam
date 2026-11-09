"""A software passkey for tests: ES256, real signatures, a counter.

It answers ``navigator.credentials.create`` and ``.get`` the way a browser
and a platform authenticator would, for any RP ID and origin. Its CBOR
encoder is written here, apart from the decoder under test.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import struct

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

UP, UV, BE, AT = 0x01, 0x04, 0x08, 0x40


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64u(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _head(major: int, n: int) -> bytes:
    if n < 24:
        return bytes([major << 5 | n])
    if n < 0x100:
        return bytes([major << 5 | 24, n])
    return bytes([major << 5 | 25]) + struct.pack(">H", n)


def _cbor(value) -> bytes:
    if isinstance(value, int):
        return _head(0, value) if value >= 0 else _head(1, -1 - value)
    if isinstance(value, bytes):
        return _head(2, len(value)) + value
    if isinstance(value, str):
        return _head(3, len(value.encode())) + value.encode()
    if isinstance(value, dict):
        return _head(5, len(value)) + b"".join(_cbor(k) + _cbor(v) for k, v in value.items())
    raise TypeError(value)


class SoftPasskey:
    def __init__(self, *, backup_eligible: bool = True, counter: int = 0) -> None:
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.credential_id = os.urandom(16)
        self.backup_eligible = backup_eligible
        self.counter = counter  # 0 stays 0, like a synced passkey

    @property
    def id(self) -> str:
        return b64u(self.credential_id)

    def _flags(self) -> int:
        return UP | UV | (BE if self.backup_eligible else 0)

    def _client_data(self, kind: str, challenge: str, origin: str) -> bytes:
        return json.dumps(
            {"type": kind, "challenge": challenge, "origin": origin, "crossOrigin": False},
            separators=(",", ":"),
        ).encode()

    def create(self, options: dict, origin: str) -> dict:
        """A ``create`` response to the relay's creation options."""
        point = self.key.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )
        cose = {1: 2, 3: -7, -1: 1, -2: point[1:33], -3: point[33:]}
        rp_hash = hashlib.sha256(options["rp"]["id"].encode()).digest()
        attested = (
            bytes(16) + struct.pack(">H", len(self.credential_id)) + self.credential_id + _cbor(cose)
        )
        auth = rp_hash + bytes([self._flags() | AT]) + struct.pack(">I", self.counter) + attested
        return {
            "id": self.id,
            "attestationObject": b64u(_cbor({"fmt": "none", "attStmt": {}, "authData": auth})),
            "clientDataJSON": b64u(self._client_data("webauthn.create", options["challenge"], origin)),
        }

    def get(self, challenge: str, *, rp_id: str, origin: str) -> dict:
        """A ``get`` response signing *challenge* (base64url)."""
        if self.counter:
            self.counter += 1
        auth = (
            hashlib.sha256(rp_id.encode()).digest()
            + bytes([self._flags()])
            + struct.pack(">I", self.counter)
        )
        client = self._client_data("webauthn.get", challenge, origin)
        signature = self.key.sign(auth + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256()))
        return {
            "credentialId": self.id,
            "authenticatorData": b64u(auth),
            "clientDataJSON": b64u(client),
            "signature": b64u(signature),
        }

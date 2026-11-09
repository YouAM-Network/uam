"""did:key for the two key types owner objects carry.

Ed25519 (an agent's key, ``did:key:z6Mk...``, multicodec 0xed) and P-256
(a passkey, ``did:key:zDn...``, multicodec 0x1200, compressed point).
"""

from __future__ import annotations

from uam.protocol.errors import UAMError

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(_B58)}

ED25519 = "ed25519"
P256 = "p256"

# multicodec prefixes, as unsigned varints
_PREFIX = {
    ED25519: bytes([0xED, 0x01]),
    P256: bytes([0x80, 0x24]),
}
_LENGTH = {ED25519: 32, P256: 33}


class InvalidDidKeyError(UAMError):
    """A did:key string that isn't one of the two supported key types."""


def b58encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    zeros = len(data) - len(data.lstrip(b"\0"))
    return "1" * zeros + out


def b58decode(text: str) -> bytes:
    n = 0
    for c in text:
        if c not in _B58_INDEX:
            raise InvalidDidKeyError(f"not base58btc: {c!r}")
        n = n * 58 + _B58_INDEX[c]
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    zeros = len(text) - len(text.lstrip("1"))
    return b"\0" * zeros + body


def encode_did_key(kind: str, public_key: bytes) -> str:
    """``did:key:z...`` for an Ed25519 key (32 bytes) or a compressed P-256 point (33 bytes)."""
    if kind not in _PREFIX:
        raise InvalidDidKeyError(f"unsupported key type: {kind}")
    if len(public_key) != _LENGTH[kind]:
        raise InvalidDidKeyError(f"{kind} key must be {_LENGTH[kind]} bytes")
    if kind == P256 and public_key[0] not in (2, 3):
        raise InvalidDidKeyError("P-256 key must be a compressed point")
    return "did:key:z" + b58encode(_PREFIX[kind] + public_key)


def decode_did_key(did: str) -> tuple[str, bytes]:
    """The key type and raw public key in a did:key string."""
    if not isinstance(did, str) or not did.startswith("did:key:z"):
        raise InvalidDidKeyError("not a did:key with base58btc multibase")
    raw = b58decode(did[len("did:key:z"):])
    for kind, prefix in _PREFIX.items():
        if raw.startswith(prefix):
            key = raw[len(prefix):]
            if len(key) != _LENGTH[kind]:
                raise InvalidDidKeyError(f"{kind} key must be {_LENGTH[kind]} bytes")
            if kind == P256 and key[0] not in (2, 3):
                raise InvalidDidKeyError("P-256 key must be a compressed point")
            return kind, key
    raise InvalidDidKeyError("unsupported key type")

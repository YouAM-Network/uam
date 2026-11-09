"""Passkeys (WebAuthn): registration, assertions and the approval challenge.

Owners approve with a passkey. The relay and the agents check the same
things, and the TS SDK has the same verifier on the same vectors:

- registration: ``webauthn.create``, attestation format ``none`` only (no
  attestation trust in the beta), user present and verified, ES256 only;
- assertion: ``webauthn.get``, the exact challenge, the published owner
  origin exactly, no cross-origin frame, ``rpIdHash`` = SHA-256(RP ID), user
  present and verified, backup eligibility unchanged since registration, an
  ES256 signature over ``authenticatorData || SHA-256(clientDataJSON)``
  (high-S accepted), and, where the stored counter is known, a counter that
  went up whenever either count is non-zero (synced passkeys keep none and
  report 0 throughout; a count that drops to 0 may be a clone).

ES256 only: a passkey's did:key must never look like an agent key, and every
FIDO2 authenticator supports it.
"""

from __future__ import annotations

import base64
import hashlib
import json
import struct
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from uam.protocol.didkey import P256, encode_did_key
from uam.protocol.errors import UAMError
from uam.protocol.signed import SignedObjectError, canonical

ES256 = -7

UP = 0x01
UV = 0x04
BE = 0x08
AT = 0x40
ED = 0x80


class WebAuthnError(UAMError):
    """A registration or assertion that fails a check."""


@dataclass(frozen=True)
class Credential:
    """A registered passkey: its id, algorithm, compressed P-256 key and flags."""

    id: bytes
    alg: int
    public_key: bytes
    backup_eligible: bool
    sign_count: int

    @property
    def did(self) -> str:
        return encode_did_key(P256, self.public_key)


# --- CBOR (the subset WebAuthn uses) ------------------------------------------


def _cbor(data: bytes, i: int) -> tuple[Any, int]:
    if i >= len(data):
        raise WebAuthnError("CBOR: truncated")
    first = data[i]
    major, info = first >> 5, first & 0x1F
    i += 1
    if major == 7:
        if info == 20:
            return False, i
        if info == 21:
            return True, i
        raise WebAuthnError("CBOR: unsupported simple value or float")
    if info < 24:
        n = info
    elif info in (24, 25, 26, 27):
        size = 1 << (info - 24)
        if i + size > len(data):
            raise WebAuthnError("CBOR: truncated")
        n = int.from_bytes(data[i:i + size], "big")
        i += size
    else:
        raise WebAuthnError("CBOR: indefinite lengths are not supported")
    if major == 0:
        return n, i
    if major == 1:
        return -1 - n, i
    if major in (2, 3):
        if i + n > len(data):
            raise WebAuthnError("CBOR: truncated")
        raw = data[i:i + n]
        i += n
        if major == 2:
            return raw, i
        try:
            return raw.decode("utf-8"), i
        except UnicodeDecodeError:
            raise WebAuthnError("CBOR: text is not UTF-8") from None
    if major == 4:
        items = []
        for _ in range(n):
            item, i = _cbor(data, i)
            items.append(item)
        return items, i
    if major == 5:
        out: dict[Any, Any] = {}
        for _ in range(n):
            key, i = _cbor(data, i)
            if not isinstance(key, (int, str)):
                raise WebAuthnError("CBOR: map keys must be integers or text")
            if key in out:
                raise WebAuthnError("CBOR: duplicate map key")
            out[key], i = _cbor(data, i)
        return out, i
    raise WebAuthnError("CBOR: tags are not supported")


def _cbor_whole(data: bytes) -> Any:
    value, end = _cbor(data, 0)
    if end != len(data):
        raise WebAuthnError("CBOR: trailing bytes")
    return value


# --- shared checks ------------------------------------------------------------


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _client_data(raw: bytes, kind: str, challenge: bytes, origin: str) -> None:
    try:
        data = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        raise WebAuthnError("clientDataJSON is not JSON") from None
    if not isinstance(data, dict):
        raise WebAuthnError("clientDataJSON is not an object")
    if data.get("type") != kind:
        raise WebAuthnError(f"clientData.type must be {kind}")
    if data.get("challenge") != _b64u(challenge):
        raise WebAuthnError("clientData.challenge doesn't match")
    if data.get("origin") != origin:
        raise WebAuthnError("clientData.origin doesn't match")
    if data.get("crossOrigin", False) is not False:
        raise WebAuthnError("cross-origin ceremonies are refused")
    if "topOrigin" in data:
        raise WebAuthnError("ceremonies in a frame are refused")


def _auth_data(data: bytes, rp_id: str) -> tuple[int, int]:
    if len(data) < 37:
        raise WebAuthnError("authenticatorData too short")
    if data[:32] != hashlib.sha256(rp_id.encode("ascii")).digest():
        raise WebAuthnError("rpIdHash doesn't match")
    flags = data[32]
    if not flags & UP:
        raise WebAuthnError("user not present")
    if not flags & UV:
        raise WebAuthnError("user not verified")
    (count,) = struct.unpack(">I", data[33:37])
    return flags, count


def _p256(public_key: bytes) -> ec.EllipticCurvePublicKey:
    try:
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public_key)
    except ValueError:
        raise WebAuthnError("not a P-256 point") from None


# --- registration -------------------------------------------------------------


def verify_registration(
    *,
    attestation_object: bytes,
    client_data_json: bytes,
    challenge: bytes,
    origin: str,
    rp_id: str,
) -> Credential:
    """Check a ``webauthn.create`` response; the passkey it registers."""
    _client_data(client_data_json, "webauthn.create", challenge, origin)
    att = _cbor_whole(attestation_object)
    if not isinstance(att, dict) or set(att) != {"fmt", "attStmt", "authData"}:
        raise WebAuthnError("attestationObject must have fmt, attStmt and authData")
    if att["fmt"] != "none" or att["attStmt"] != {}:
        raise WebAuthnError("only attestation format 'none' is accepted")
    data = att["authData"]
    if not isinstance(data, bytes):
        raise WebAuthnError("authData must be bytes")
    flags, count = _auth_data(data, rp_id)
    if not flags & AT:
        raise WebAuthnError("no attested credential data")
    if len(data) < 55:
        raise WebAuthnError("attested credential data too short")
    (id_len,) = struct.unpack(">H", data[53:55])
    credential_id = data[55:55 + id_len]
    if len(credential_id) != id_len:
        raise WebAuthnError("credential id truncated")
    cose, end = _cbor(data, 55 + id_len)
    if not flags & ED and end != len(data):
        raise WebAuthnError("trailing bytes after the credential key")
    # kty EC2, alg ES256, crv P-256; other COSE parameters are ignored.
    if not isinstance(cose, dict) or (cose.get(1), cose.get(3), cose.get(-1)) != (2, ES256, 1):
        raise WebAuthnError("only ES256 (P-256) passkeys are accepted")
    x, y = cose.get(-2), cose.get(-3)
    if not (isinstance(x, bytes) and isinstance(y, bytes) and len(x) == len(y) == 32):
        raise WebAuthnError("bad P-256 coordinates")
    key = _p256(b"\x04" + x + y)
    return Credential(
        id=credential_id,
        alg=ES256,
        public_key=key.public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint
        ),
        backup_eligible=bool(flags & BE),
        sign_count=count,
    )


# --- assertions ----------------------------------------------------------------


def verify_assertion(
    credential: Credential,
    *,
    authenticator_data: bytes,
    client_data_json: bytes,
    signature: bytes,
    challenge: bytes,
    origin: str,
    rp_id: str,
    check_counter: bool = True,
) -> int:
    """Check a ``webauthn.get`` response from *credential*; its new sign count.

    ``check_counter=False`` is for a verifier without the stored counter (an
    agent checking an approval offline); the relay always checks it.
    """
    if credential.alg != ES256:
        raise WebAuthnError("only ES256 (P-256) passkeys are accepted")
    _client_data(client_data_json, "webauthn.get", challenge, origin)
    flags, count = _auth_data(authenticator_data, rp_id)
    if bool(flags & BE) is not credential.backup_eligible:
        raise WebAuthnError("backup eligibility changed since registration")
    key = _p256(credential.public_key)
    signed = authenticator_data + hashlib.sha256(client_data_json).digest()
    try:
        key.verify(signature, signed, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise WebAuthnError("bad signature") from None
    if check_counter and (count or credential.sign_count) and count <= credential.sign_count:
        raise WebAuthnError("sign count didn't go up: the passkey may have been cloned")
    return count


# --- approvals -----------------------------------------------------------------


def approval_challenge(items: list[tuple[str, str]], screen: str) -> bytes:
    """The challenge one Face ID signs to approve *items* (type, hash) as shown.

    ``screen`` is the exact text the page showed; the challenge commits to
    its SHA-256, so the page can't show one thing and get another signed.
    """
    if not items:
        raise WebAuthnError("an approval covers at least one object")
    body = {
        "set": [{"t": t, "h": h} for t, h in items],
        "screen": hashlib.sha256(screen.encode("utf-8")).hexdigest(),
    }
    try:
        data = canonical(body)
    except SignedObjectError as exc:
        raise WebAuthnError(f"bad approval set: {exc}") from None
    return hashlib.sha256(b"UAM-APPROVAL-v1\n" + data).digest()

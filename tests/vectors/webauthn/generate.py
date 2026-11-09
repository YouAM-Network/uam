"""Write the WebAuthn vectors shared by the Python and TS test suites.

Run from the repo root: ``python tests/vectors/webauthn/generate.py``.

A software authenticator (fixed keys, deterministic ECDSA) makes one
registration and one assertion per algorithm, then each rejection case
changes exactly one thing. Its CBOR encoder is written here, separately
from the decoder under test.
"""

from __future__ import annotations

import base64
import hashlib
import json
import struct
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

HERE = Path(__file__).parent
RP_ID = "youam.network"
ORIGIN = "https://account.youam.network"
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

UP, UV, BE, BS, AT = 0x01, 0x04, 0x08, 0x10, 0x40


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


# --- minimal CBOR encoder (major types 0, 1, 2, 3, 4, 5) ---------------------


def _head(major: int, n: int) -> bytes:
    if n < 24:
        return bytes([major << 5 | n])
    if n < 0x100:
        return bytes([major << 5 | 24, n])
    if n < 0x10000:
        return bytes([major << 5 | 25]) + struct.pack(">H", n)
    return bytes([major << 5 | 26]) + struct.pack(">I", n)


def cbor(value) -> bytes:
    if isinstance(value, bool):
        return bytes([0xF5 if value else 0xF4])
    if isinstance(value, int):
        return _head(0, value) if value >= 0 else _head(1, -1 - value)
    if isinstance(value, bytes):
        return _head(2, len(value)) + value
    if isinstance(value, str):
        data = value.encode()
        return _head(3, len(data)) + data
    if isinstance(value, list):
        return _head(4, len(value)) + b"".join(cbor(v) for v in value)
    if isinstance(value, dict):
        return _head(5, len(value)) + b"".join(cbor(k) + cbor(v) for k, v in value.items())
    raise TypeError(value)


# --- the software authenticator -----------------------------------------------


class Authenticator:
    def __init__(self, alg: int, seed: str) -> None:
        self.alg = alg
        secret = hashlib.sha256(seed.encode()).digest()
        if alg == -7:
            self.key = ec.derive_private_key(int.from_bytes(secret, "big") % P256_N, ec.SECP256R1())
        else:
            self.key = ed25519.Ed25519PrivateKey.from_private_bytes(secret)
        self.credential_id = hashlib.sha256(b"cred-" + seed.encode()).digest()[:16]

    def cose_key(self) -> dict:
        pub = self.key.public_key()
        if self.alg == -7:
            point = pub.public_bytes(serialization.Encoding.X962,
                                     serialization.PublicFormat.UncompressedPoint)
            return {1: 2, 3: -7, -1: 1, -2: point[1:33], -3: point[33:]}
        raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return {1: 1, 3: -8, -1: 6, -2: raw}

    def public_key(self) -> bytes:
        pub = self.key.public_key()
        if self.alg == -7:
            return pub.public_bytes(serialization.Encoding.X962,
                                    serialization.PublicFormat.CompressedPoint)
        return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def sign(self, data: bytes) -> bytes:
        if self.alg == -7:
            return self.key.sign(data, ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
        return self.key.sign(data)


def auth_data(flags: int, count: int, *, rp_id: str = RP_ID, attested: bytes = b"") -> bytes:
    return hashlib.sha256(rp_id.encode()).digest() + bytes([flags]) + struct.pack(">I", count) + attested


def client_data(kind: str, challenge: bytes, **overrides) -> bytes:
    data = {"type": kind, "challenge": b64u(challenge), "origin": ORIGIN, "crossOrigin": False}
    data.update(overrides)
    for key in [k for k, v in data.items() if v is None]:
        del data[key]
    return json.dumps(data, separators=(",", ":")).encode()


CHALLENGE = hashlib.sha256(b"registration challenge").digest()
GET_CHALLENGE = hashlib.sha256(b"approval challenge").digest()


def registration(auth: Authenticator, *, flags: int = UP | UV | BE | AT, fmt: str = "none",
                 cose: dict | None = None, att_stmt: dict | None = None,
                 with_key: bool = True, **client) -> dict:
    attested = (bytes(16) + struct.pack(">H", len(auth.credential_id)) + auth.credential_id
                + cbor(cose if cose is not None else auth.cose_key()))
    ad = auth_data(flags, 0, attested=attested if with_key else b"")
    obj = cbor({"fmt": fmt, "attStmt": att_stmt if att_stmt is not None else {}, "authData": ad})
    return {
        "attestationObject": b64u(obj),
        "clientDataJSON": b64u(client_data(client.pop("type", "webauthn.create"),
                                           client.pop("challenge", CHALLENGE), **client)),
    }


def assertion(auth: Authenticator, *, flags: int = UP | UV | BE, count: int = 7,
              rp_id: str = RP_ID, high_s: bool = False, tamper: bool = False, **client) -> dict:
    ad = auth_data(flags, count, rp_id=rp_id)
    cd = client_data(client.pop("type", "webauthn.get"), client.pop("challenge", GET_CHALLENGE),
                     **client)
    sig = auth.sign(ad + hashlib.sha256(cd).digest())
    if high_s:
        r, s = decode_dss_signature(sig)
        sig = encode_dss_signature(r, s if s > P256_N // 2 else P256_N - s)
    if tamper:
        ad = ad[:-1] + bytes([ad[-1] ^ 1])
    return {"authenticatorData": b64u(ad), "clientDataJSON": b64u(cd), "signature": b64u(sig)}


def main() -> None:
    es = Authenticator(-7, "es256")
    ed = Authenticator(-8, "eddsa")
    other = Authenticator(-7, "someone-else")
    expected = {"rpId": RP_ID, "origin": ORIGIN}

    def credential(auth: Authenticator, *, backup_eligible: bool = True, sign_count: int = 5):
        return {"alg": auth.alg, "publicKey": auth.public_key().hex(),
                "backupEligible": backup_eligible, "signCount": sign_count}

    registrations = [
        {"name": "es256", "ok": True, "response": registration(es),
         "challenge": b64u(CHALLENGE), "credential": {
             "id": b64u(es.credential_id), **credential(es, sign_count=0)}},
        {"name": "not_backup_eligible", "ok": True,
         "response": registration(es, flags=UP | UV | AT), "challenge": b64u(CHALLENGE),
         "credential": {"id": b64u(es.credential_id),
                        **credential(es, backup_eligible=False, sign_count=0)}},
        {"name": "extra_cose_parameter", "ok": True,
         "response": registration(es, cose={**es.cose_key(), -4: b"ignored"}),
         "challenge": b64u(CHALLENGE),
         "credential": {"id": b64u(es.credential_id), **credential(es, sign_count=0)}},
    ]
    bad_registrations = {
        "eddsa_not_supported": registration(ed),
        "get_not_create": registration(es, type="webauthn.get"),
        "wrong_challenge": registration(es, challenge=GET_CHALLENGE),
        "wrong_origin": registration(es, origin="https://youam.network"),
        "cross_origin": registration(es, crossOrigin=True),
        "packed_attestation": registration(es, fmt="packed", att_stmt={"alg": -7, "sig": b"x"}),
        "none_with_statement": registration(es, att_stmt={"x": 1}),
        "no_attested_data": registration(es, flags=UP | UV | BE, with_key=False),
        "at_flag_clear": registration(es, flags=UP | UV | BE),
        "no_user_verification": registration(es, flags=UP | BE | AT),
        "rs256_key": registration(es, cose={1: 3, 3: -257, -1: b"\x01" * 256, -2: b"\x01\x00\x01"}),
        "alg_does_not_match_key": registration(es, cose={**es.cose_key(), 3: -8}),
        "point_not_on_curve": registration(es, cose={**es.cose_key(), -3: bytes(32)}),
    }
    for name, response in bad_registrations.items():
        registrations.append({"name": name, "ok": False, "response": response,
                              "challenge": b64u(CHALLENGE)})

    assertions = [
        {"name": "es256", "ok": True, "credential": credential(es), "response": assertion(es),
         "signCount": 7},
        {"name": "high_s_accepted", "ok": True, "credential": credential(es),
         "response": assertion(es, high_s=True), "signCount": 7},
        {"name": "no_counter_synced_passkey", "ok": True,
         "credential": credential(es, sign_count=0), "response": assertion(es, count=0),
         "signCount": 0},
        {"name": "counter_started", "ok": True, "credential": credential(es, sign_count=0),
         "response": assertion(es, count=3), "signCount": 3},
        {"name": "cross_origin_absent", "ok": True, "credential": credential(es),
         "response": assertion(es, crossOrigin=None), "signCount": 7},
    ]
    bad_assertions = {
        "create_not_get": (credential(es), assertion(es, type="webauthn.create")),
        "wrong_challenge": (credential(es), assertion(es, challenge=CHALLENGE)),
        "wrong_origin": (credential(es), assertion(es, origin="https://youam.network")),
        "origin_with_slash": (credential(es), assertion(es, origin=ORIGIN + "/")),
        "cross_origin": (credential(es), assertion(es, crossOrigin=True)),
        "top_origin": (credential(es), assertion(es, topOrigin=ORIGIN)),
        "wrong_rp_id": (credential(es), assertion(es, rp_id="evil.example")),
        "no_user_present": (credential(es), assertion(es, flags=UV | BE)),
        "no_user_verification": (credential(es), assertion(es, flags=UP | BE)),
        "backup_eligibility_changed": (credential(es), assertion(es, flags=UP | UV)),
        "tampered_auth_data": (credential(es), assertion(es, tamper=True)),
        "someone_elses_key": (credential(other), assertion(es)),
        "eddsa_credential": (credential(ed), assertion(ed)),
        "credential_alg_not_es256": ({**credential(es), "alg": -8}, assertion(es)),
        "counter_went_back": (credential(es, sign_count=7), assertion(es, count=7)),
        # WebAuthn L3: a counter that drops to 0 after being non-zero may be a clone.
        "counter_reset_to_zero": (credential(es, sign_count=9), assertion(es, count=0)),
    }
    for name, (cred, response) in bad_assertions.items():
        assertions.append({"name": name, "ok": False, "credential": cred, "response": response})

    approval = {
        "set": [{"t": "UamContactGrant", "h": "A" * 43}, {"t": "UamRedemption", "h": "B" * 43}],
        "screen": "Connect with Bob Smith (b•••@acme.com)",
    }
    screen_hex = hashlib.sha256(approval["screen"].encode()).hexdigest()
    jcs = json.dumps({"set": approval["set"], "screen": screen_hex}, sort_keys=True,
                     separators=(",", ":"))
    approval["challenge"] = b64u(hashlib.sha256(b"UAM-APPROVAL-v1\n" + jcs.encode()).digest())

    out = {"rpId": RP_ID, "origin": ORIGIN, "getChallenge": b64u(GET_CHALLENGE),
           "registrations": registrations, "assertions": assertions, "approval": approval}
    (HERE / "vectors.json").write_text(json.dumps(out, indent=1, ensure_ascii=False) + "\n")
    _ = expected


if __name__ == "__main__":
    main()

"""Write the signed-object vectors shared by the Python and TS test suites.

Run from the repo root: ``python tests/vectors/signed/generate.py``.

Expected canonical forms and hashes come from ``json.dumps(sort_keys=True,
separators=(",", ":"))``, which equals RFC 8785 for bodies inside the profile
(ASCII strings, integers only), not from uam.protocol.signed: the vectors
check the implementation, they aren't produced by it.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).parent

H1 = "A" * 43  # a well-formed hash (43 base64url chars)
H2 = "B" * 43
OWNER_ID = "C" * 22
NONCE = "nonce-0123456789ab"
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58(data: bytes) -> str:
    n, out = int.from_bytes(data, "big"), ""
    while n:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + out


def _key(seed: str, length: int) -> bytes:
    return hashlib.sha256(seed.encode()).digest()[:length]


def did(kind: str, key: bytes) -> str:
    prefix = {"ed25519": bytes([0xED, 0x01]), "p256": bytes([0x80, 0x24])}[kind]
    return "did:key:z" + _b58(prefix + key)


ED_KEY = _key("agent-bob", 32)
P256_KEY = b"\x02" + _key("passkey-alice", 32)
P256_KEY_2 = b"\x03" + _key("passkey-old", 32)
ED_DID = did("ed25519", ED_KEY)
P256_DID = did("p256", P256_KEY)
P256_DID_2 = did("p256", P256_KEY_2)


def oracle_canonical(body: dict) -> str:
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def oracle_hash(body: dict) -> str:
    data = f"UAM-{body['type']}-v1\n".encode() + oracle_canonical(body).encode()
    return base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()


owner_ref = {"relay": "youam.network", "ownerId": OWNER_ID, "keysHash": H1}

VALID = {
    "owner_keys_entry0": {
        "type": "UamOwnerKeys", "v": 1, "owner": {"relay": "youam.network"}, "seq": 0,
        "keys": [{"id": P256_DID, "rpId": "youam.network", "backupEligible": True,
                  "label": "Alice iPhone"}],
    },
    "owner_keys_punctuated_label": {
        "type": "UamOwnerKeys", "v": 1, "owner": {"relay": "youam.network"}, "seq": 0,
        "keys": [{"id": P256_DID, "rpId": "youam.network", "backupEligible": True,
                  "label": "Alice's iPhone (work) #2"}],
    },
    "owner_keys_later": {
        "type": "UamOwnerKeys", "v": 1, "owner": {"relay": "youam.network", "ownerId": OWNER_ID},
        "seq": 3, "prev": H1,
        "keys": [{"id": P256_DID, "rpId": "youam.network", "backupEligible": False, "label": "Key"}],
        "removed": [{"id": P256_DID_2,
                     "reason": "compromised"}],
    },
    "owner_link": {
        "type": "UamOwnerLink", "v": 1, "owner": owner_ref, "agent": "bob::youam.network",
        "agentKey": ED_DID, "relay": "youam.network", "via": "setup", "shared": True,
        "effectiveAt": "2026-11-12T10:00:00Z", "validFrom": "2026-11-09T10:00:00Z", "nonce": NONCE,
    },
    "owner_unlink": {
        "type": "UamOwnerUnlink", "v": 1, "owner": owner_ref, "agent": "bob::youam.network",
        "agentKey": ED_DID, "reason": "owner", "validFrom": "2026-11-09T10:00:00Z", "nonce": NONCE,
    },
    # Reserved for names given out by a domain or namespace (DEC-006): the
    # authority took the name back, or the name lapsed. Nothing sends them yet.
    "owner_unlink_authority": {
        "type": "UamOwnerUnlink", "v": 1, "owner": owner_ref, "agent": "bob::youam.network",
        "agentKey": ED_DID, "reason": "authority", "validFrom": "2026-11-09T10:00:00Z",
        "nonce": NONCE,
    },
    "owner_unlink_lapsed": {
        "type": "UamOwnerUnlink", "v": 1, "owner": owner_ref, "agent": "bob::youam.network",
        "agentKey": ED_DID, "reason": "lapsed", "validFrom": "2026-11-09T10:00:00Z", "nonce": NONCE,
    },
    "invite_preapproved": {
        "type": "UamInvite", "v": 1, "inviter": owner_ref,
        "offer": {"actions": ["message"], "locations": ["shared"]},
        "ask": {"actions": ["message"], "locations": ["shared"]},
        "secretHash": H1, "emailHash": H2, "mode": "preapproved", "maxUses": 1,
        "validFrom": "2026-11-09T10:00:00Z", "redeemBy": "2026-11-16T10:00:00Z", "nonce": NONCE,
    },
    "invite_confirm": {
        "type": "UamInvite", "v": 1, "inviter": owner_ref,
        "offer": {"actions": ["message"], "locations": ["alice-research::youam.network"]},
        "ask": {"actions": ["message"], "locations": ["shared"]},
        "secretHash": H1, "mode": "confirm", "maxUses": 1,
        "validFrom": "2026-11-09T10:00:00Z", "redeemBy": "2026-11-09T10:10:00Z", "nonce": NONCE,
    },
    "redemption": {
        "type": "UamRedemption", "v": 1, "invite": H1, "secret": "s" * 22, "invitee": owner_ref,
        "issuer": P256_DID, "createdAt": "2026-11-09T10:05:00Z", "nonce": NONCE,
    },
    "grant_owner": {
        "type": "UamContactGrant", "v": 1, "issuer": P256_DID,
        "issuerOwner": {"relay": "youam.network", "ownerId": OWNER_ID},
        "credentialSubject": {"kind": "owner", "owner": owner_ref},
        "authorization_details": [{"type": "uam_contact", "actions": ["message"],
                                   "locations": ["shared"]}],
        "via": "intro_email", "enforcer": "youam.network",
        "validFrom": "2026-11-09T10:00:00Z", "validUntil": "2027-02-07T10:00:00Z", "nonce": NONCE,
    },
    "grant_invitee": {
        "type": "UamContactGrant", "v": 1, "issuer": P256_DID,
        "issuerOwner": {"relay": "youam.network", "ownerId": OWNER_ID},
        "credentialSubject": {"kind": "invitee", "invite": H1},
        "authorization_details": [{"type": "uam_contact", "actions": ["message"],
                                   "locations": ["shared"]}],
        "via": "intro_email", "enforcer": "youam.network",
        "validFrom": "2026-11-09T10:00:00Z", "validUntil": "2026-12-09T10:00:00Z", "nonce": NONCE,
    },
    "grant_agent_with_ext": {
        "type": "UamContactGrant", "v": 1, "issuer": P256_DID,
        "issuerOwner": {"relay": "youam.network", "ownerId": OWNER_ID},
        "credentialSubject": {"kind": "agent", "id": ED_DID, "address": "carol::x.example"},
        "authorization_details": [{"type": "uam_contact", "actions": ["message"],
                                   "locations": ["bob-research::youam.network", "bob::youam.network"]}],
        "via": "request", "enforcer": "youam.network",
        "validFrom": "2026-11-09T10:00:00Z", "validUntil": "2026-11-10T10:00:00Z", "nonce": NONCE,
        "ext": {"note": "not critical"}, "crit": [],
    },
}


def broken(name: str, change) -> dict:
    body = copy.deepcopy(VALID[name])
    change(body)
    return body


def _set(path, value):
    def change(body):
        target = body
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = value
    return change


def _drop(key):
    return lambda body: body.pop(key)


INVALID_OBJECTS = {
    "unknown_member": broken("owner_link", _set(["color"], "blue")),
    "unknown_nested_member": broken("owner_link", _set(["owner", "extra"], "x")),
    "missing_member": broken("owner_link", _drop("nonce")),
    "wrong_version": broken("owner_link", _set(["v"], 2)),
    "unknown_type": broken("owner_link", _set(["type"], "UamSomethingElse")),
    "bool_as_int": broken("owner_link", _set(["v"], True)),
    "int_as_bool": broken("owner_link", _set(["shared"], 1)),
    "bad_time": broken("owner_link", _set(["validFrom"], "2026-11-09T10:00:00.000Z")),
    "impossible_date": broken("owner_link", _set(["validFrom"], "2026-02-30T10:00:00Z")),
    "bad_via": broken("owner_link", _set(["via"], "magic")),
    "bad_agent_key": broken("owner_link", _set(["agentKey"], P256_DID)),
    "bad_address": broken("owner_link", _set(["agent"], "Bob::YouAM.network")),
    "bad_hash_length": broken("owner_link", _set(["owner", "keysHash"], "A" * 42)),
    "bad_hash_chars": broken("owner_link", _set(["owner", "keysHash"], "+" * 43)),
    "short_nonce": broken("owner_link", _set(["nonce"], "abc")),
    "entry0_with_owner_id": broken("owner_keys_entry0", _set(["owner", "ownerId"], OWNER_ID)),
    "entry0_with_prev": broken("owner_keys_entry0", _set(["prev"], H1)),
    "later_without_prev": broken("owner_keys_later", _drop("prev")),
    "later_without_owner_id": broken("owner_keys_later", lambda b: b["owner"].pop("ownerId")),
    "no_keys": broken("owner_keys_later", _set(["keys"], [])),
    # A label is quoted in the text an owner signs, so it can't hold a quote.
    "label_with_quote": broken("owner_keys_entry0", _set(["keys", 0, "label"],
                                                         'Laptop" to your account. Remove "Phone')),
    "label_too_long": broken("owner_keys_entry0", _set(["keys", 0, "label"], "x" * 65)),
    "bad_removed_reason": broken("owner_keys_later", _set(["removed", 0, "reason"], "lost")),
    "unlink_unknown_reason": broken("owner_unlink", _set(["reason"], "expired")),
    "preapproved_without_email": broken("invite_preapproved", _drop("emailHash")),
    "two_uses": broken("invite_preapproved", _set(["maxUses"], 2)),
    "redeem_too_late": broken("invite_preapproved", _set(["redeemBy"], "2026-11-16T10:00:01Z")),
    "redeem_before_valid": broken("invite_preapproved", _set(["redeemBy"], "2026-11-09T09:59:59Z")),
    "unknown_action": broken("invite_preapproved", _set(["offer", "actions"], ["approve"])),
    "empty_locations": broken("invite_preapproved", _set(["offer", "locations"], [])),
    "bad_location": broken("invite_preapproved", _set(["offer", "locations"], ["everywhere"])),
    "grant_too_long": broken("grant_owner", _set(["validUntil"], "2027-02-07T10:00:01Z")),
    "grant_unknown_subject": broken("grant_owner", _set(["credentialSubject", "kind"], "team")),
    "grant_subject_mixed": broken("grant_invitee", _set(["credentialSubject", "owner"], owner_ref)),
    "grant_agent_needs_ed25519": broken("grant_agent_with_ext",
                                        _set(["credentialSubject", "id"], P256_DID)),
    "grant_issuer_not_passkey": broken("grant_owner", _set(["issuer"], ED_DID)),
    "grant_bad_detail_type": broken("grant_owner",
                                    _set(["authorization_details", 0, "type"], "other")),
    "grant_no_details": broken("grant_owner", _set(["authorization_details"], [])),
    "unknown_critical_ext": broken("grant_agent_with_ext", _set(["crit"], ["note"])),
    "crit_names_missing_ext": broken("grant_agent_with_ext", _set(["crit"], ["absent"])),
    "crit_without_ext": broken("grant_owner", _set(["crit"], [])),
    "ext_not_object": broken("grant_agent_with_ext", _set(["ext"], "x")),
}

# Raw texts: what the parser itself must refuse (or accept), before any schema.
PROFILE = [
    {"name": "plain", "text": '{"a":1,"b":"x"}', "ok": True, "canonical": '{"a":1,"b":"x"}'},
    {"name": "sorted_and_compacted", "text": '{ "b" : [true, false],\n "a" : {"d":1,"c":2} }',
     "ok": True, "canonical": '{"a":{"c":2,"d":1},"b":[true,false]}'},
    {"name": "escapes_kept", "text": '{"a":"q\\"b\\\\c"}', "ok": True,
     "canonical": '{"a":"q\\"b\\\\c"}'},
    {"name": "unicode_escape_of_ascii", "text": '{"a":"\\u0041"}', "ok": True,
     "canonical": '{"a":"A"}'},
    {"name": "max_int", "text": '{"a":9007199254740991,"b":-9007199254740991}', "ok": True,
     "canonical": '{"a":9007199254740991,"b":-9007199254740991}'},
    {"name": "duplicate_key", "text": '{"a":1,"a":2}', "ok": False},
    {"name": "nested_duplicate_key", "text": '{"a":{"b":1,"b":1}}', "ok": False},
    {"name": "float", "text": '{"a":1.5}', "ok": False},
    {"name": "float_whole", "text": '{"a":1.0}', "ok": False},
    {"name": "exponent", "text": '{"a":1e3}', "ok": False},
    {"name": "negative_zero", "text": '{"a":-0}', "ok": False},
    {"name": "too_big", "text": '{"a":9007199254740992}', "ok": False},
    {"name": "too_small", "text": '{"a":-9007199254740992}', "ok": False},
    {"name": "null", "text": '{"a":null}', "ok": False},
    {"name": "non_ascii", "text": '{"a":"café"}', "ok": False},
    {"name": "non_ascii_escaped", "text": '{"a":"caf\\u00e9"}', "ok": False},
    {"name": "control_char", "text": '{"a":"x\\ny"}', "ok": False},
    {"name": "non_ascii_key", "text": '{"é":1}', "ok": False},
    {"name": "top_level_array", "text": "[1]", "ok": False},
    {"name": "nan", "text": '{"a":NaN}', "ok": False},
    {"name": "trailing_garbage", "text": '{"a":1} x', "ok": False},
    {"name": "trailing_comma", "text": '{"a":1,}', "ok": False},
    {"name": "leading_zero", "text": '{"a":01}', "ok": False},
    # RFC 8785 §3.2.3's example sorts non-ASCII keys and §3.2.2.3 encodes
    # floats: both fall outside the profile and must be refused, not encoded.
    {"name": "rfc8785_sorting_example",
     "text": '{"\\u20ac":"Euro Sign","\\r":"Carriage Return","1":"One"}', "ok": False},
    {"name": "rfc8785_numbers_example", "text": '{"numbers":[333333333.33333329,1E30,4.50]}',
     "ok": False},
]


def main() -> None:
    objects = []
    for name, body in VALID.items():
        objects.append({"name": name, "body": body, "ok": True,
                        "canonical": oracle_canonical(body), "hash": oracle_hash(body)})
    for name, body in INVALID_OBJECTS.items():
        objects.append({"name": name, "body": body, "ok": False})
    (HERE / "objects.json").write_text(json.dumps(objects, indent=1) + "\n")
    didkeys = [
        {"kind": "ed25519", "key": ED_KEY.hex(), "did": ED_DID, "ok": True},
        {"kind": "p256", "key": P256_KEY.hex(), "did": P256_DID, "ok": True},
        {"kind": "p256", "key": P256_KEY_2.hex(), "did": P256_DID_2, "ok": True},
        {"kind": "ed25519", "key": "00" * 32, "did": did("ed25519", bytes(32)), "ok": True},
        {"name": "short_ed25519", "did": did("ed25519", ED_KEY[:31]), "ok": False},
        {"name": "uncompressed_p256", "did": did("p256", b"\x04" + _key("x", 32)), "ok": False},
        {"name": "unknown_codec", "did": "did:key:z" + _b58(bytes([0xE7, 0x01]) + ED_KEY),
         "ok": False},
        {"name": "not_base58", "did": "did:key:z0OIl", "ok": False},
        {"name": "not_multibase_z", "did": "did:key:f" + ED_KEY.hex(), "ok": False},
        {"name": "other_method", "did": "did:web:example.com", "ok": False},
    ]
    (HERE / "didkey.json").write_text(json.dumps(didkeys, indent=1) + "\n")
    (HERE / "profile.json").write_text(json.dumps(PROFILE, indent=1, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    main()

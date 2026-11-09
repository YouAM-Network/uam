"""Signed owner objects: profile, canonical form, hash and schemas.

Every owner object (key log entries, links, invites, redemptions, grants) is
a JSON body in a restricted profile, hashed as

    h = base64url(SHA-256("UAM-<type>-v1\\n" || JCS(body)))   (no padding)

where ``<type>`` is the body's own ``type``. The profile keeps RFC 8785 (JCS)
simple and the same in every language: printable ASCII strings, integers
within +/-(2^53-1), no floats, no nulls, no duplicate keys, and no members a
type doesn't define (new ones go under ``ext``, with ``crit`` naming the ones
a verifier must understand), so an old verifier can never over-grant.

A body that breaks any rule is refused, never repaired.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from uam.protocol.address import parse_address
from uam.protocol.didkey import ED25519, P256, InvalidDidKeyError, decode_did_key
from uam.protocol.errors import InvalidAddressError, UAMError

MAX_INT = 2**53 - 1
GRANT_MAX_DAYS = 90
INVITE_MAX_DAYS = 7


class SignedObjectError(UAMError):
    """A signed-object body outside the profile or its type's schema."""


# --- profile -----------------------------------------------------------------


def _reject_constant(name: str) -> Any:
    raise SignedObjectError(f"not allowed: {name}")


def _reject_float(text: str) -> Any:
    raise SignedObjectError(f"floats are not allowed: {text}")


def _parse_int(text: str) -> int:
    if text == "-0":
        raise SignedObjectError("-0 is not allowed")
    value = int(text)
    if abs(value) > MAX_INT:
        raise SignedObjectError(f"integer out of range: {text}")
    return value


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise SignedObjectError(f"duplicate key: {key!r}")
        out[key] = value
    return out


def parse_body(text: str | bytes) -> dict[str, Any]:
    """Parse a body, refusing anything outside the profile."""
    if isinstance(text, bytes):
        try:
            text = text.decode("utf-8")
        except UnicodeDecodeError:
            raise SignedObjectError("body is not UTF-8") from None
    try:
        body = json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_float=_reject_float,
            parse_int=_parse_int,
            parse_constant=_reject_constant,
        )
    except SignedObjectError:
        raise
    except (ValueError, RecursionError) as exc:
        raise SignedObjectError(f"not JSON: {exc}") from None
    if not isinstance(body, dict):
        raise SignedObjectError("a body must be a JSON object")
    _check_profile(body)
    return body


def _check_string(value: str) -> None:
    if not all(0x20 <= ord(c) <= 0x7E for c in value):
        raise SignedObjectError("strings must be printable ASCII")


def _check_profile(value: Any) -> None:
    if isinstance(value, bool):
        return
    if isinstance(value, int):
        if abs(value) > MAX_INT:
            raise SignedObjectError(f"integer out of range: {value}")
        return
    if isinstance(value, str):
        _check_string(value)
        return
    if isinstance(value, list):
        for item in value:
            _check_profile(item)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise SignedObjectError("keys must be strings")
            _check_string(key)
            _check_profile(item)
        return
    if value is None:
        raise SignedObjectError("null is not allowed")
    raise SignedObjectError(f"not allowed: {type(value).__name__}")


def _encode(value: Any) -> str:
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
    if isinstance(value, list):
        return "[" + ",".join(_encode(item) for item in value) + "]"
    return "{" + ",".join(
        _encode(key) + ":" + _encode(value[key]) for key in sorted(value)
    ) + "}"


def canonical(body: dict[str, Any]) -> bytes:
    """RFC 8785 canonical form (inside the profile: sorted keys, no whitespace)."""
    if not isinstance(body, dict):
        raise SignedObjectError("a body must be a JSON object")
    _check_profile(body)
    return _encode(body).encode("ascii")


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _hash_canonical(body: dict[str, Any]) -> str:
    prefix = f"UAM-{body['type']}-v1\n".encode("ascii")
    return _b64u(hashlib.sha256(prefix + canonical(body)).digest())


def object_hash(body: dict[str, Any]) -> str:
    """The object's hash; the body is validated first."""
    validate(body)
    return _hash_canonical(body)


# --- schemas -----------------------------------------------------------------

Check = Callable[[Any, str], None]

_TIME_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_HASH_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")
_OWNER_ID_RE = re.compile(r"^[A-Za-z0-9_-]{22}$")
_NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{16,64}$")
_SECRET_RE = re.compile(r"^[A-Za-z0-9_-]{22}$")
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$")


def _fail(path: str, why: str) -> None:
    raise SignedObjectError(f"{path}: {why}")


def _string(value: Any, path: str) -> None:
    if not isinstance(value, str) or not value:
        _fail(path, "must be a non-empty string")


def _label(value: Any, path: str) -> None:
    _string(value, path)
    if len(value) > 64:
        _fail(path, "at most 64 characters")


def _matching(regex: re.Pattern[str], what: str) -> Check:
    def check(value: Any, path: str) -> None:
        if not isinstance(value, str) or not regex.match(value):
            _fail(path, f"must be {what}")
    return check


_hash = _matching(_HASH_RE, "a hash (43 base64url characters)")
_owner_id = _matching(_OWNER_ID_RE, "an owner id (22 base64url characters)")
_nonce = _matching(_NONCE_RE, "a nonce (16-64 base64url characters)")
_secret = _matching(_SECRET_RE, "a secret (22 base64url characters)")
_domain = _matching(_DOMAIN_RE, "a lowercase domain")


def _time(value: Any, path: str) -> None:
    if not isinstance(value, str) or not _TIME_RE.match(value):
        _fail(path, "must be YYYY-MM-DDTHH:MM:SSZ")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        _fail(path, "not a real time")


def _parse_time(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _bool(value: Any, path: str) -> None:
    if not isinstance(value, bool):
        _fail(path, "must be true or false")


def _const(expected: Any) -> Check:
    def check(value: Any, path: str) -> None:
        if type(value) is not type(expected) or value != expected:
            _fail(path, f"must be {expected!r}")
    return check


def _one_of(*options: str) -> Check:
    def check(value: Any, path: str) -> None:
        if value not in options or not isinstance(value, str):
            _fail(path, f"must be one of {', '.join(options)}")
    return check


def _uint(value: Any, path: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        _fail(path, "must be a non-negative integer")


def _address(value: Any, path: str) -> None:
    if not isinstance(value, str):
        _fail(path, "must be an address")
    try:
        parsed = parse_address(value)
    except InvalidAddressError:
        _fail(path, "must be an address")
    if parsed.full != value:
        _fail(path, "must be an address in canonical (lowercase) form")


def _did(kind: str) -> Check:
    def check(value: Any, path: str) -> None:
        try:
            found, _ = decode_did_key(value)
        except InvalidDidKeyError as exc:
            _fail(path, str(exc))
        if found != kind:
            _fail(path, f"must be a {kind} did:key")
    return check


def _list(item: Check, *, min_len: int = 1, max_len: int = 64) -> Check:
    def check(value: Any, path: str) -> None:
        if not isinstance(value, list) or not min_len <= len(value) <= max_len:
            _fail(path, f"must be a list of {min_len}-{max_len} items")
        for i, entry in enumerate(value):
            item(entry, f"{path}[{i}]")
    return check


def _object(required: dict[str, Check], optional: dict[str, Check] | None = None) -> Check:
    optional = optional or {}

    def check(value: Any, path: str) -> None:
        if not isinstance(value, dict):
            _fail(path, "must be an object")
        for key in value:
            if key not in required and key not in optional:
                _fail(f"{path}.{key}", "unknown member")
        for key, member in required.items():
            if key not in value:
                _fail(f"{path}.{key}", "missing")
            member(value[key], f"{path}.{key}")
        for key, member in optional.items():
            if key in value:
                member(value[key], f"{path}.{key}")
    return check


def _location(value: Any, path: str) -> None:
    if value != "shared":
        _address(value, path)


_access = _object({
    "actions": _list(_one_of("message"), max_len=1),
    "locations": _list(_location),
})

_owner_ref = _object({"relay": _domain, "ownerId": _owner_id, "keysHash": _hash})
_owner_ref_no_keys = _object({"relay": _domain, "ownerId": _owner_id})

_passkey = _did(P256)
_agent_key = _did(ED25519)

_KEYS_OWNER = _object({"relay": _domain}, {"ownerId": _owner_id})


def _ext(body: dict[str, Any]) -> None:
    """``ext`` holds extensions; ``crit`` names those a verifier must know (none yet)."""
    if "ext" in body and not isinstance(body["ext"], dict):
        _fail("ext", "must be an object")
    if "crit" in body:
        crit = body["crit"]
        if "ext" not in body:
            _fail("crit", "needs ext")
        if not isinstance(crit, list) or not all(isinstance(k, str) for k in crit):
            _fail("crit", "must be a list of ext keys")
        for key in crit:
            if key not in body["ext"]:
                _fail(f"crit.{key}", "not in ext")
            _fail(f"crit.{key}", "unknown critical extension")


_EXT = {"ext": lambda v, p: None, "crit": lambda v, p: None}


def _owner_keys(body: dict[str, Any]) -> None:
    _object(
        {
            "type": _const("UamOwnerKeys"), "v": _const(1), "owner": _KEYS_OWNER,
            "seq": _uint,
            "keys": _list(_object({
                "id": _passkey, "rpId": _domain, "backupEligible": _bool, "label": _label,
            }), max_len=16),
        },
        {
            "prev": _hash,
            "removed": _list(_object({
                "id": _passkey, "reason": _one_of("removed", "compromised"),
            }), max_len=64),
            "recovery": _bool,
            **_EXT,
        },
    )(body, "$")
    first = body["seq"] == 0
    if first and ("ownerId" in body["owner"] or "prev" in body):
        # The owner id is the hash of entry 0, so entry 0 can't contain it.
        _fail("$", "entry 0 has no owner.ownerId and no prev")
    if not first and ("ownerId" not in body["owner"] or "prev" not in body):
        _fail("$", "a later entry needs owner.ownerId and prev")


def _owner_link(body: dict[str, Any]) -> None:
    _object({
        "type": _const("UamOwnerLink"), "v": _const(1), "owner": _owner_ref,
        "agent": _address, "agentKey": _agent_key, "relay": _domain,
        "via": _one_of("setup", "link"), "shared": _bool,
        "effectiveAt": _time, "validFrom": _time, "nonce": _nonce,
    }, dict(_EXT))(body, "$")


def _owner_unlink(body: dict[str, Any]) -> None:
    _object({
        "type": _const("UamOwnerUnlink"), "v": _const(1), "owner": _owner_ref,
        "agent": _address, "agentKey": _agent_key,
        "reason": _one_of("owner", "admin", "relink"),
        "validFrom": _time, "nonce": _nonce,
    }, dict(_EXT))(body, "$")


def _invite(body: dict[str, Any]) -> None:
    _object(
        {
            "type": _const("UamInvite"), "v": _const(1), "inviter": _owner_ref,
            "offer": _access, "ask": _access, "secretHash": _hash,
            "mode": _one_of("preapproved", "confirm"), "maxUses": _const(1),
            "validFrom": _time, "redeemBy": _time, "nonce": _nonce,
        },
        {"emailHash": _hash, **_EXT},
    )(body, "$")
    if body["mode"] == "preapproved" and "emailHash" not in body:
        _fail("$.emailHash", "a pre-approved invite names the invitee's email")
    span = _parse_time(body["redeemBy"]) - _parse_time(body["validFrom"])
    if not timedelta(0) < span <= timedelta(days=INVITE_MAX_DAYS):
        _fail("$.redeemBy", f"must be after validFrom, within {INVITE_MAX_DAYS} days")


def _redemption(body: dict[str, Any]) -> None:
    _object({
        "type": _const("UamRedemption"), "v": _const(1), "invite": _hash,
        "secret": _secret, "invitee": _owner_ref, "issuer": _passkey,
        "createdAt": _time, "nonce": _nonce,
    }, dict(_EXT))(body, "$")


_SUBJECTS: dict[str, Check] = {
    "owner": _object({"kind": _const("owner"), "owner": _owner_ref}),
    "invitee": _object({"kind": _const("invitee"), "invite": _hash}),
    "agent": _object({"kind": _const("agent"), "id": _agent_key, "address": _address}),
}


def _subject(value: Any, path: str) -> None:
    kind = value.get("kind") if isinstance(value, dict) else None
    if kind not in _SUBJECTS:
        _fail(f"{path}.kind", f"must be one of {', '.join(_SUBJECTS)}")
    _SUBJECTS[kind](value, path)


def _grant(body: dict[str, Any]) -> None:
    _object({
        "type": _const("UamContactGrant"), "v": _const(1), "issuer": _passkey,
        "issuerOwner": _owner_ref_no_keys, "credentialSubject": _subject,
        "authorization_details": _list(_object({
            "type": _const("uam_contact"),
            "actions": _list(_one_of("message"), max_len=1),
            "locations": _list(_location),
        }), max_len=8),
        "via": _one_of("intro_email", "intro_code", "intro_qr", "request", "carried_over"),
        "enforcer": _domain, "validFrom": _time, "validUntil": _time, "nonce": _nonce,
    }, dict(_EXT))(body, "$")
    span = _parse_time(body["validUntil"]) - _parse_time(body["validFrom"])
    if not timedelta(0) < span <= timedelta(days=GRANT_MAX_DAYS):
        _fail("$.validUntil", f"must be after validFrom, within {GRANT_MAX_DAYS} days")


SCHEMAS: dict[str, Callable[[dict[str, Any]], None]] = {
    "UamOwnerKeys": _owner_keys,
    "UamOwnerLink": _owner_link,
    "UamOwnerUnlink": _owner_unlink,
    "UamInvite": _invite,
    "UamRedemption": _redemption,
    "UamContactGrant": _grant,
}


def validate(body: Any) -> None:
    """Refuse a body outside the profile or its type's schema."""
    if not isinstance(body, dict):
        raise SignedObjectError("a body must be a JSON object")
    _check_profile(body)
    schema = SCHEMAS.get(body.get("type"))  # type: ignore[arg-type]
    if schema is None:
        raise SignedObjectError(f"unknown type: {body.get('type')!r}")
    schema(body)
    _ext(body)

"""The owner key log: which passkeys speak for an owner (P2c-2, v2 §4.1).

A chain of ``UamOwnerKeys`` entries. Entry 0 lists the owner's first
passkeys and is signed by one of them; the owner id is the first 22
characters of its hash, so no relay can make up an owner. Every later
entry names the owner and the hash of the entry before it, lists the keys
from then on, and is signed with a passkey from the entry before it.

Each signature is a WebAuthn assertion over the approval challenge for the
entry and the text the owner was shown (``screen_for``), which is fixed by
the entry, so a verifier recomputes it.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field
from typing import Any

from uam.protocol.didkey import P256, InvalidDidKeyError, decode_did_key
from uam.protocol.errors import UAMError
from uam.protocol.signed import SignedObjectError, canonical, object_hash, parse_body, validate
from uam.protocol.webauthn import ES256, Credential, WebAuthnError, approval_challenge, verify_assertion

TYPE = "UamOwnerKeys"
OWNER_ID_LENGTH = 22


class KeyLogError(UAMError):
    """A key log entry, or a whole chain, that fails a check."""


@dataclass(frozen=True)
class KeyLog:
    """What a verified chain says now."""

    owner_id: str
    relay: str
    seq: int
    head: str
    keys: dict[str, dict[str, Any]] = field(default_factory=dict)


def owner_id_of(entry0_hash: str) -> str:
    return entry0_hash[:OWNER_ID_LENGTH]


def _checked(body: dict[str, Any]) -> dict[str, Any]:
    try:
        validate(body)
    except SignedObjectError as exc:
        raise KeyLogError(str(exc)) from None
    ids = [k["id"] for k in body["keys"]]
    if len(set(ids)) != len(ids):
        raise KeyLogError("a key is listed twice")
    return body


def next_entry(
    previous: dict[str, Any] | None,
    *,
    relay: str | None = None,
    add: list[dict[str, Any]] | None = None,
    remove: list[tuple[str, str]] | None = None,
) -> dict[str, Any]:
    """The entry after *previous* (None: entry 0 on *relay*) that adds the key
    entries in *add* and drops the (did, reason) pairs in *remove*."""
    add, remove = list(add or []), list(remove or [])
    if previous is None:
        if relay is None or not add or remove:
            raise KeyLogError("entry 0 needs a relay and at least one key, and removes nothing")
        return _checked({"type": TYPE, "v": 1, "owner": {"relay": relay}, "seq": 0, "keys": add})
    if not add and not remove:
        raise KeyLogError("a new entry must add or remove a key")
    current = {k["id"]: k for k in previous["keys"]}
    for key in add:
        if key["id"] in current:
            raise KeyLogError(f"{key['label']!r} is already a key")
    dropped = {did for did, _ in remove}
    for did in dropped:
        if did not in current:
            raise KeyLogError(f"{did} is not a current key")
    keys = [k for k in previous["keys"] if k["id"] not in dropped] + add
    if not keys:
        raise KeyLogError("the last key can't be removed")
    prev_hash = object_hash(previous)
    body: dict[str, Any] = {
        "type": TYPE,
        "v": 1,
        "owner": {
            "relay": previous["owner"]["relay"],
            "ownerId": previous["owner"].get("ownerId") or owner_id_of(prev_hash),
        },
        "seq": previous["seq"] + 1,
        "prev": prev_hash,
        "keys": keys,
    }
    if remove:
        body["removed"] = [{"id": did, "reason": reason} for did, reason in remove]
    return _checked(body)


def _labels(keys: list[dict[str, Any]]) -> str:
    return ", ".join(f'"{k["label"]}"' for k in keys)


def screen_for(body: dict[str, Any], previous: dict[str, Any] | None) -> str:
    """The text the owner is shown to sign *body* (v1; fixed by the entry)."""
    if previous is None:
        noun = "passkey" if len(body["keys"]) == 1 else "passkeys"
        return (
            f"Create your UAM owner account on {body['owner']['relay']} "
            f"with the {noun} {_labels(body['keys'])}."
        )
    before = {k["id"]: k for k in previous["keys"]}
    lines = []
    added = [k for k in body["keys"] if k["id"] not in before]
    if added:
        noun = "passkey" if len(added) == 1 else "passkeys"
        lines.append(f"Add the {noun} {_labels(added)} to your UAM owner account.")
    for item in body.get("removed", []):
        label = _labels([before[item["id"]]]) if item["id"] in before else item["id"]
        if item["reason"] == "compromised":
            lines.append(f"Remove the passkey {label} from your UAM owner account as compromised.")
        else:
            lines.append(f"Remove the passkey {label} from your UAM owner account.")
    return " ".join(lines)


def entry_challenge(entry_hash: str, screen: str) -> bytes:
    """The WebAuthn challenge that signs one key log entry as shown."""
    return approval_challenge([(TYPE, entry_hash)], screen)


def _unb64u(text: Any, what: str) -> bytes:
    if not isinstance(text, str):
        raise KeyLogError(f"{what} must be base64url")
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError):
        raise KeyLogError(f"{what} must be base64url") from None


def _follows(body: dict[str, Any], previous: dict[str, Any]) -> None:
    """*body*'s keys are *previous*'s, minus what it removes, plus new ones."""
    before = {k["id"] for k in previous["keys"]}
    now = {k["id"] for k in body["keys"]}
    removed = {r["id"] for r in body.get("removed", [])}
    if not removed <= before:
        raise KeyLogError("removes a key that wasn't there")
    if removed & now:
        raise KeyLogError("removes a key and keeps it")
    if (before - now) - removed:
        raise KeyLogError("drops a key without removing it")
    if now == before and not removed:
        raise KeyLogError("changes nothing")


def _verify_entry(
    i: int, entry: dict[str, Any], previous: dict[str, Any] | None, state: KeyLog | None,
    *, rp_id: str, origin: str,
) -> tuple[dict[str, Any], KeyLog]:
    try:
        text = entry["body"]
        body = parse_body(text)
        validate(body)
    except (KeyError, TypeError) as exc:
        raise KeyLogError(f"missing {exc}") from None
    except SignedObjectError as exc:
        raise KeyLogError(str(exc)) from None
    if body["type"] != TYPE:
        raise KeyLogError("not a UamOwnerKeys entry")
    if canonical(body).decode() != text:
        raise KeyLogError("body isn't in canonical form")
    entry_hash = object_hash(body)
    if entry.get("hash") != entry_hash:
        raise KeyLogError("hash doesn't match the body")
    if body["seq"] != i or entry.get("seq") != i:
        raise KeyLogError(f"expected seq {i}")
    ids = [k["id"] for k in body["keys"]]
    if len(set(ids)) != len(ids):
        raise KeyLogError("a key is listed twice")
    for key in body["keys"]:
        if key["rpId"] != rp_id:
            raise KeyLogError(f"key {key['label']!r} is for RP ID {key['rpId']!r}, not {rp_id!r}")

    if previous is None or state is None:
        signers = {k["id"]: k for k in body["keys"]}
        owner_id, relay = owner_id_of(entry_hash), body["owner"]["relay"]
    else:
        if body["owner"].get("relay") != state.relay:
            raise KeyLogError("names a different relay")
        if body["owner"].get("ownerId") != state.owner_id:
            raise KeyLogError("names a different owner")
        if body.get("prev") != state.head:
            raise KeyLogError("prev isn't the entry before")
        _follows(body, previous)
        signers = state.keys
        owner_id, relay = state.owner_id, state.relay

    screen = screen_for(body, previous)
    if entry.get("screen") != screen:
        raise KeyLogError("screen isn't the text for this entry")
    signer = entry.get("signer")
    if signer not in signers:
        raise KeyLogError("signed by a key that may not sign it")
    try:
        kind, public_key = decode_did_key(signer)
    except InvalidDidKeyError as exc:
        raise KeyLogError(str(exc)) from None
    if kind != P256:
        raise KeyLogError("signer isn't a passkey")
    credential = Credential(
        id=b"", alg=ES256, public_key=public_key,
        backup_eligible=signers[signer]["backupEligible"], sign_count=0,
    )
    try:
        verify_assertion(
            credential,
            authenticator_data=_unb64u(entry.get("authenticatorData"), "authenticatorData"),
            client_data_json=_unb64u(entry.get("clientDataJSON"), "clientDataJSON"),
            signature=_unb64u(entry.get("signature"), "signature"),
            challenge=entry_challenge(entry_hash, screen),
            origin=origin,
            rp_id=rp_id,
            check_counter=False,
        )
    except WebAuthnError as exc:
        raise KeyLogError(str(exc)) from None
    return body, KeyLog(
        owner_id=owner_id, relay=relay, seq=i, head=entry_hash,
        keys={k["id"]: k for k in body["keys"]},
    )


def verify_key_log(entries: list[dict[str, Any]], *, rp_id: str, origin: str) -> KeyLog:
    """Check a whole chain from entry 0; what it says now.

    *rp_id* and *origin* are the owner's relay's published ``rp_id`` and
    ``owner_origin``. Counters aren't checked (that needs the relay's state).
    """
    if not entries:
        raise KeyLogError("a key log has at least entry 0")
    previous: dict[str, Any] | None = None
    state: KeyLog | None = None
    for i, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise KeyLogError(f"entry {i}: must be an object")
        try:
            previous, state = _verify_entry(i, entry, previous, state, rp_id=rp_id, origin=origin)
        except KeyLogError as exc:
            raise KeyLogError(f"entry {i}: {exc}") from None
    assert state is not None
    return state

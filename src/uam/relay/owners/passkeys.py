"""Owner passkeys and the key log (P2c-2, spec P2 §3.2).

Registering is two ceremonies: ``create`` makes the passkey (held), then
``get`` signs the key log entry that adds it. Entry 0 is signed by the
passkey it adds and makes the owner id; a later entry must be signed by an
active passkey from the entry before. Challenges last 5 minutes and work
once; the relay checks sign counts.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
from datetime import timedelta
from typing import Any

from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from uam.db.crud import owners as crud
from uam.db.models import Owner, OwnerKeyLogEntry, OwnerPasskey
from uam.protocol.keylog import KeyLogError, entry_challenge, next_entry, owner_id_of, screen_for
from uam.protocol.signed import canonical, object_hash, parse_body
from uam.protocol.webauthn import (
    ES256,
    Credential,
    WebAuthnError,
    verify_assertion,
    verify_registration,
)
from uam.relay.owners import service

MAX_PASSKEYS = 16  # UamOwnerKeys lists at most 16 keys
CHALLENGE_TTL = timedelta(minutes=5)


class PasskeyError(Exception):
    """Refused: *status* and a stable *code* for the JSON answer."""

    def __init__(self, status: int, code: str, detail: str) -> None:
        super().__init__(detail)
        self.status, self.code, self.detail = status, code, detail


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64u(text: str, what: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError):
        raise PasskeyError(400, "bad_request", f"{what} must be base64url") from None


def _client_challenge(client_data_json: bytes) -> str:
    """The challenge a clientDataJSON claims, to find our record of it (the
    WebAuthn check then compares it exactly)."""
    try:
        challenge = json.loads(client_data_json)["challenge"]
    except (ValueError, KeyError, TypeError):
        raise PasskeyError(400, "bad_request", "clientDataJSON has no challenge") from None
    if not isinstance(challenge, str):
        raise PasskeyError(400, "bad_request", "clientDataJSON has no challenge")
    return challenge


async def _claim(session: AsyncSession, owner: Owner, purpose: str, challenge: str):
    row = await crud.find_challenge(session, owner.id, purpose, challenge)
    now = service.utcnow()
    if row is None or row.used_at is not None or service._aware(row.expires_at) <= now:
        raise PasskeyError(400, "bad_challenge", "That request has expired. Start again.")
    if not await crud.use_challenge(session, row.id, now):
        raise PasskeyError(400, "bad_challenge", "That request has expired. Start again.")
    return row


async def register_options(
    session: AsyncSession, settings, *, owner: Owner, email: str, user_handle: str
) -> dict[str, Any]:
    """Creation options for ``navigator.credentials.create``."""
    now = service.utcnow()
    await crud.drop_stale_held(session, owner.id, now - CHALLENGE_TTL)
    active = await crud.passkeys(session, owner.id)
    if len(active) >= MAX_PASSKEYS:
        await session.commit()
        raise PasskeyError(409, "too_many_passkeys", f"An owner has at most {MAX_PASSKEYS} passkeys.")
    challenge = _b64u(os.urandom(32))
    await crud.add_challenge(
        session, owner_pk=owner.id, purpose="register", challenge=challenge, now=now,
        expires_at=now + CHALLENGE_TTL,
    )
    await session.commit()
    return {
        "rp": {"id": settings.rp_id, "name": "UAM"},
        "user": {"id": user_handle, "name": email, "displayName": email},
        "challenge": challenge,
        "pubKeyCredParams": [{"type": "public-key", "alg": ES256}],
        "authenticatorSelection": {
            "residentKey": "required", "requireResidentKey": True, "userVerification": "required",
        },
        "attestation": "none",
        "excludeCredentials": [{"type": "public-key", "id": p.credential_id} for p in active],
        "timeout": int(CHALLENGE_TTL.total_seconds() * 1000),
    }


async def _approval(
    session: AsyncSession, owner: Owner, body: dict[str, Any], previous: dict[str, Any] | None,
    *, passkey: OwnerPasskey, allow: list[str], rp_id: str,
) -> dict[str, Any]:
    """Store an approve challenge for *body* and say what to sign."""
    now = service.utcnow()
    entry_hash = object_hash(body)
    screen = screen_for(body, previous)
    challenge = _b64u(entry_challenge(entry_hash, screen))
    text = canonical(body).decode()
    await crud.add_challenge(
        session, owner_pk=owner.id, purpose="approve", challenge=challenge, now=now,
        expires_at=now + CHALLENGE_TTL, passkey_pk=passkey.id, body=text, screen=screen,
    )
    return {
        "body": text, "hash": entry_hash, "screen": screen, "challenge": challenge,
        "allowCredentials": allow, "rpId": rp_id,
    }


async def register_finish(
    session: AsyncSession, settings, *, owner: Owner,
    attestation_object: str, client_data_json: str, label: str,
) -> dict[str, Any]:
    """Check a ``create`` response, hold the passkey, and ask to sign the
    key log entry that adds it."""
    client = _unb64u(client_data_json, "clientDataJSON")
    attestation = _unb64u(attestation_object, "attestationObject")
    row = await _claim(session, owner, "register", _client_challenge(client))
    try:
        credential = verify_registration(
            attestation_object=attestation, client_data_json=client,
            challenge=_unb64u(row.challenge, "challenge"),
            origin=settings.owner_origin, rp_id=settings.rp_id,
        )
    except WebAuthnError as exc:
        await session.commit()
        raise PasskeyError(400, "bad_passkey", str(exc)) from None
    active = await crud.passkeys(session, owner.id)
    if len(active) >= MAX_PASSKEYS:
        await session.commit()
        raise PasskeyError(409, "too_many_passkeys", f"An owner has at most {MAX_PASSKEYS} passkeys.")

    head = await crud.key_log_head(session, owner.id)
    previous = parse_body(head.body) if head else None
    key = {
        "id": credential.did, "rpId": settings.rp_id,
        "backupEligible": credential.backup_eligible, "label": label,
    }
    try:
        body = next_entry(previous, relay=settings.relay_domain, add=[key])
    except KeyLogError as exc:
        await session.commit()
        raise PasskeyError(409, "bad_entry", str(exc)) from None

    passkey = OwnerPasskey(
        owner_pk=owner.id, credential_id=_b64u(credential.id),
        public_key=_b64u(credential.public_key), did=credential.did,
        backup_eligible=credential.backup_eligible, sign_count=credential.sign_count,
        label=label, state="held", created_at=service.utcnow(),
    )
    session.add(passkey)
    try:
        await session.flush()
    except IntegrityError:
        await session.rollback()
        raise PasskeyError(409, "passkey_exists", "That passkey is already registered.") from None
    allow = [passkey.credential_id] if previous is None else [p.credential_id for p in active]
    answer = await _approval(
        session, owner, body, previous, passkey=passkey, allow=allow, rp_id=settings.rp_id
    )
    await session.commit()
    return answer


async def sign_entry(
    session: AsyncSession, settings, *, owner: Owner, credential_id: str,
    authenticator_data: str, client_data_json: str, signature: str,
) -> dict[str, Any]:
    """Check a ``get`` response for a pending entry and append it."""
    client = _unb64u(client_data_json, "clientDataJSON")
    auth = _unb64u(authenticator_data, "authenticatorData")
    sig = _unb64u(signature, "signature")
    row = await _claim(session, owner, "approve", _client_challenge(client))
    body = parse_body(row.body)
    head = await crud.key_log_head(session, owner.id)

    async def refuse(status: int, code: str, detail: str) -> PasskeyError:
        await session.commit()  # the challenge stays used
        return PasskeyError(status, code, detail)

    if body["seq"] == 0:
        if head is not None:
            raise await refuse(409, "log_moved", "Your passkeys changed meanwhile. Start again.")
        signers = {row.passkey_pk}
    else:
        if head is None or body.get("prev") != head.hash:
            raise await refuse(409, "log_moved", "Your passkeys changed meanwhile. Start again.")
        allowed = {k["id"] for k in parse_body(head.body)["keys"]}
        signers = {p.id for p in await crud.passkeys(session, owner.id) if p.did in allowed}
    signer = await crud.passkey_by_credential(session, owner.id, credential_id)
    if signer is None or signer.id not in signers:
        raise await refuse(400, "bad_signer", "That passkey can't approve this change.")
    try:
        count = verify_assertion(
            Credential(
                id=_unb64u(signer.credential_id, "credentialId"), alg=ES256,
                public_key=_unb64u(signer.public_key, "publicKey"),
                backup_eligible=signer.backup_eligible, sign_count=signer.sign_count,
            ),
            authenticator_data=auth, client_data_json=client, signature=sig,
            challenge=_unb64u(row.challenge, "challenge"),
            origin=settings.owner_origin, rp_id=settings.rp_id,
        )
    except WebAuthnError as exc:
        raise await refuse(400, "bad_passkey", str(exc)) from None

    entry_hash = object_hash(body)
    signer.sign_count = count
    session.add(OwnerKeyLogEntry(
        owner_pk=owner.id, seq=body["seq"], body=row.body, hash=entry_hash, signer=signer.did,
        authenticator_data=authenticator_data, client_data_json=client_data_json,
        signature=signature, screen=row.screen, created_at=service.utcnow(),
    ))
    try:
        await session.flush()
    except IntegrityError:
        await session.rollback()
        raise PasskeyError(409, "log_moved", "Your passkeys changed meanwhile. Start again.") from None
    added = await session.get(OwnerPasskey, row.passkey_pk)
    if added is not None:
        added.state = "active"
    if body["seq"] == 0:
        owner.owner_id = owner_id_of(entry_hash)
    await crud.audit(session, owner.id, "key_log_signed", {"seq": body["seq"]})
    await session.commit()
    return {"seq": body["seq"], "hash": entry_hash, "owner_id": owner.owner_id}


async def list_passkeys(session: AsyncSession, owner: Owner) -> list[dict[str, Any]]:
    return [
        {
            "id": p.credential_id, "label": p.label, "did": p.did,
            "backupEligible": p.backup_eligible,
            "createdAt": service._aware(p.created_at).isoformat().replace("+00:00", "Z"),
        }
        for p in await crud.passkeys(session, owner.id)
    ]


async def public_log(session: AsyncSession, owner_id: str, since: int) -> list[dict[str, Any]] | None:
    owner = await crud.owner_by_owner_id(session, owner_id)
    if owner is None:
        return None
    return [
        {
            "seq": e.seq, "body": e.body, "hash": e.hash, "signer": e.signer,
            "authenticatorData": e.authenticator_data, "clientDataJSON": e.client_data_json,
            "signature": e.signature, "screen": e.screen,
        }
        for e in await crud.key_log(session, owner.id, since)
    ]

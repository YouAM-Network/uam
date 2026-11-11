"""Linking agents to owners (P2d, spec P2 §4).

The owner makes a code on their page. The agent redeems it; the relay
builds the ``UamOwnerLink`` body and the agent signs it first. The owner
then sees the agent and its four words and signs with a passkey. A
``setup`` code is for an agent registered after it and links at once; a
``link`` code is for an existing agent and starts 72 hours after it is
redeemed, so a stolen session can't quietly take over an agent. Until a
link starts it gives nothing, and the owner can cancel it without a
passkey. Unlinking needs the owner's passkey, or the relay admin, and
closes the agent's inbound policy.
"""

from __future__ import annotations

import base64
import json
import logging
import os
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from uam.db.crud import inbound as inbound_crud
from uam.db.crud import owner_links as crud
from uam.db.crud import owners as owner_crud
from uam.db.models import Agent, Owner, OwnerLink, OwnerPasskey, OwnerUnlink, Reservation
from uam.protocol.crypto import deserialize_verify_key, sign_message
from uam.protocol.didkey import ED25519, encode_did_key
from uam.protocol.links import (
    LINK,
    UNLINK,
    LinkError,
    link_challenge,
    link_screen,
    links_challenge,
    links_screen,
    relay_sig_message,
    unlink_challenge,
    unlink_screen,
    verify_agent_signature,
    words_for,
)
from uam.protocol.signed import _parse_time as parse_time
from uam.protocol.signed import canonical, object_hash, parse_body
from uam.protocol.webauthn import ES256, Credential, WebAuthnError, verify_assertion
from uam.relay.owners import service
from uam.relay.owners.crypto import EmailVault, new_link_code, normalise_link_code
from uam.relay.owners.passkeys import (
    CHALLENGE_TTL,
    PasskeyError,
    _b64u,
    _claim,
    _client_challenge,
    _unb64u,
)

log = logging.getLogger("uam.relay.owners")

KINDS = ("setup", "link")
CODE_TTL = timedelta(minutes=10)
#: A code for several agents (a fleet) lasts longer: they're set up in turn.
FLEET_CODE_TTL = timedelta(minutes=30)
MAX_FLEET = 25
TRIES = 5
TRY_WINDOW = timedelta(minutes=10)
LINK_DELAY = timedelta(hours=72)

#: Told when an existing agent asks to be linked, and when an agent
#: cancels its own link: (owner_pk, link view). P2g sends the owner an
#: email instead (with a cancel link for the first).
LinkNotice = Callable[[int, dict[str, Any]], None]


def log_notice(owner_pk: int, link: dict[str, Any]) -> None:
    if link["state"] == "cancelled":
        log.warning("owner %d: agent %s cancelled its link", owner_pk, link["agent"])
        return
    log.warning(
        "owner %d: agent %s asked to be linked; starts %s unless cancelled",
        owner_pk, link["agent"], link["effectiveAt"],
    )


def _stamp(value: datetime) -> str:
    return service._aware(value).strftime("%Y-%m-%dT%H:%M:%SZ")


def _nonce() -> str:
    return base64.urlsafe_b64encode(os.urandom(16)).rstrip(b"=").decode()


def show_code(code: str) -> str:
    return f"{code[:4]}-{code[4:]}"


def mask(email: str) -> str:
    """``ada@example.com`` → ``a•••@example.com``."""
    local, _, domain = email.partition("@")
    return f"{local[:1]}•••@{domain}"


async def _account(session: AsyncSession, vault: EmailVault, owner_pk: int) -> str:
    email = await owner_crud.primary_email(session, owner_pk)
    return mask(vault.decrypt(email.email_enc)) if email else ""


def view(link: OwnerLink, now: datetime) -> dict[str, Any]:
    """A link as the owner's page lists it."""
    effective_at = service._aware(link.effective_at)
    return {
        "id": link.id,
        "agent": link.agent_address,
        "agentKey": link.agent_key,
        "words": words_for(link.agent_key),
        "via": link.via,
        "state": "waiting" if link.state == "agent_signed" else link.state,
        "effectiveAt": _stamp(effective_at),
        "effective": link.state == "active" and effective_at <= now,
        "private": link.private,
        "createdAt": _stamp(link.created_at),
        "approvedAt": _stamp(link.approved_at) if link.approved_at else None,
        "endedAt": _stamp(link.ended_at) if link.ended_at else None,
        "fleet": link.fleet_id,
    }


# --- codes (owner) ------------------------------------------------------------


async def make_code(
    session: AsyncSession, vault: EmailVault, owner: Owner, kind: str, count: int = 1,
    *, reservation_id: int | None = None, fleet: str | None = None,
) -> dict[str, Any]:
    """A code for one agent (10 minutes) or for up to 25 (30 minutes). A
    setup code for a reserved name (*reservation_id*) is for that name only.
    A code naming a *fleet* (found or made) puts the agents that use it there."""
    from uam.relay.owners import fleets

    if owner.owner_id is None:
        raise PasskeyError(409, "no_passkey", "Add a passkey first.")
    now = service.utcnow()
    expires_at = now + (FLEET_CODE_TTL if count > 1 else CODE_TTL)
    group = await fleets.find_or_make(session, owner, fleet) if fleet else None
    code = new_link_code()
    row = await crud.add_code(
        session, owner_pk=owner.id, kind=kind, code_hash=vault.link_code_hash(code),
        now=now, expires_at=expires_at, max_uses=count, reservation_id=reservation_id,
    )
    row.fleet_id = group.id if group else None
    await owner_crud.audit(session, owner.id, "code_made",
                           {"kind": kind, "count": count, "fleet": row.fleet_id})
    await session.commit()
    return {
        "code": show_code(code), "kind": kind, "count": count, "expiresAt": _stamp(expires_at),
        "fleet": {"id": group.id, "name": group.name} if group else None,
    }


# --- the agent's side -----------------------------------------------------------


def _bad_code() -> PasskeyError:
    return PasskeyError(400, "bad_code", "That code didn't work. Ask your owner for a new one.")


async def start(
    session: AsyncSession, settings, vault: EmailVault, agent: Agent, typed: str
) -> dict[str, Any]:
    """Redeem a code: build the link body for the agent to sign."""
    now = service.utcnow()
    address = agent.address
    await crud.drop_tries_before(session, address, now - TRY_WINDOW)
    if await crud.tries_since(session, address, now - TRY_WINDOW) >= TRIES:
        await session.commit()
        raise PasskeyError(429, "too_many_tries", "Too many wrong codes. Wait ten minutes.")
    await crud.add_try(session, address, now)
    await session.commit()  # the try counts whatever happens next

    code = normalise_link_code(typed)
    row = await crud.code_by_hash(session, vault.link_code_hash(code)) if code else None
    if (
        row is None or row.used_at is not None or service._aware(row.expires_at) <= now
        or row.id != await crud.newest_code_id(session, row.owner_pk, row.kind)
    ):
        raise _bad_code()
    owner = await session.get(Owner, row.owner_pk)
    head = await owner_crud.key_log_head(session, row.owner_pk)
    if owner is None or owner.status != "active" or owner.owner_id is None or head is None:
        raise _bad_code()
    if row.reservation_id is not None:  # a code for a reserved name is for that name only
        held = await session.get(Reservation, row.reservation_id)
        if held is None or held.address != address:
            raise _bad_code()
    if row.kind == "setup" and service._aware(agent.created_at) <= service._aware(row.created_at):
        raise PasskeyError(
            409, "needs_link_code",
            "This agent was set up before the code was made. Ask your owner for a link code.",
        )
    # One live link per agent: the unique live_for index refuses a second
    # (at the insert below). An earlier start the agent never signed gives way.
    live = await crud.live_link(session, address)
    if live is not None:
        await crud.move_link(session, live.id, ("started",), state="cancelled", live_for=None,
                             ended_at=now)
    if not await crud.use_code(session, row.id, now, address):
        await session.rollback()
        raise _bad_code()

    link = await new_link(session, settings, owner, head.hash, agent, row.kind, now)
    link.fleet_id = row.fleet_id
    await owner_crud.audit(session, owner.id, "link_started", {"link": link.id, "via": row.kind})
    await session.commit()
    return {
        "link": link.id, "body": link.body, "hash": link.hash,
        "account": await _account(session, vault, owner.id), "words": words_for(link.agent_key),
    }


def agent_key_of(agent: Agent) -> str:
    return encode_did_key(ED25519, bytes(deserialize_verify_key(agent.public_key)))


def _link_body(
    settings, owner: Owner, keys_hash: str, agent: str, agent_key: str, via: str, now: datetime
) -> dict[str, Any]:
    valid_from = now.replace(microsecond=0)
    effective_at = valid_from + (LINK_DELAY if via == "link" else timedelta(0))
    return {
        "type": LINK, "v": 1,
        "owner": {"relay": settings.relay_domain, "ownerId": owner.owner_id, "keysHash": keys_hash},
        "agent": agent, "agentKey": agent_key, "relay": settings.relay_domain,
        "via": via, "shared": True,
        "effectiveAt": _stamp(effective_at), "validFrom": _stamp(valid_from), "nonce": _nonce(),
    }


async def new_link(
    session: AsyncSession, settings, owner: Owner, keys_hash: str, agent: Agent, via: str,
    now: datetime,
) -> OwnerLink:
    """Build a link body for *agent* to sign first and add it, ``started``.

    The unique live_for index allows one live link per agent: a second
    rolls back and is refused."""
    agent_key = agent_key_of(agent)
    body = _link_body(settings, owner, keys_hash, agent.address, agent_key, via, now)
    link = OwnerLink(
        owner_pk=owner.id, agent_address=agent.address, agent_key=agent_key,
        body=canonical(body).decode(), hash=object_hash(body), via=via,
        effective_at=parse_time(body["effectiveAt"]), state="started",
        live_for=agent.address, created_at=now,
    )
    session.add(link)
    try:
        await session.flush()
    except IntegrityError:
        await session.rollback()
        raise PasskeyError(409, "already_linked", "This agent is already linked or waiting.") from None
    return link


def rebuild(settings, owner: Owner, link: OwnerLink, now: datetime) -> None:
    """New times and nonce for a link the agent hasn't signed yet, so a body
    built a while ago still passes the agent's clock check (and a ``link``
    still starts 72 hours after the agent sees it)."""
    old = parse_body(link.body)
    body = _link_body(settings, owner, old["owner"]["keysHash"], link.agent_address,
                      link.agent_key, link.via, now)
    link.body, link.hash = canonical(body).decode(), object_hash(body)
    link.effective_at = parse_time(body["effectiveAt"])


async def agent_sign(
    session: AsyncSession, agent: Agent, link_hash: str, signature: str, notice: LinkNotice
) -> dict[str, Any]:
    """The agent's signature on the body it was given."""
    link = await crud.live_link(session, agent.address)
    if link is None or link.hash != link_hash:
        raise PasskeyError(404, "no_link", "No link is waiting for this agent's signature.")
    try:
        verify_agent_signature(parse_body(link.body), signature)
    except LinkError:
        raise PasskeyError(400, "bad_signature", "That signature doesn't match the link.") from None
    if not await crud.move_link(session, link.id, ("started",), state="agent_signed",
                                agent_signature=signature):
        await session.rollback()
        raise PasskeyError(404, "no_link", "No link is waiting for this agent's signature.")
    await owner_crud.audit(session, link.owner_pk, "link_agent_signed", {"link": link.id})
    await session.commit()
    await session.refresh(link)
    if link.via == "link":
        notice(link.owner_pk, view(link, service.utcnow()))
    return {"state": "waiting_for_owner"}


async def agent_cancel(session: AsyncSession, agent: Agent, notice: LinkNotice) -> dict[str, Any]:
    """Whoever runs the agent ends a link that hasn't started yet.

    The agent's token is enough: it only narrows. Once the link is in
    effect the agent can't end it (an agent never unlinks itself)."""
    link = await crud.live_link(session, agent.address)
    if link is None:
        raise PasskeyError(404, "no_link", "This agent has no link to cancel.")
    now = service.utcnow()
    if link.state == "active" and service._aware(link.effective_at) <= now:
        raise PasskeyError(
            409, "not_cancellable", "This link is in effect. Only its owner can unlink it.",
        )
    if not await crud.move_link(session, link.id, (link.state,), state="cancelled",
                                live_for=None, ended_at=now):
        await session.rollback()
        raise PasskeyError(409, "not_cancellable", "This link changed. Check its state again.")
    await owner_crud.audit(session, link.owner_pk, "link_cancelled", {"link": link.id, "by": "agent"})
    await session.commit()
    await session.refresh(link)
    if link.agent_signature is not None:  # the owner never saw an unsigned one
        notice(link.owner_pk, view(link, now))
    return {"state": "cancelled"}


_AGENT_STATES = {
    "started": "waiting_for_agent", "agent_signed": "waiting_for_owner",
    "cancelled": "cancelled", "unlinked": "unlinked",
}


async def agent_status(session: AsyncSession, vault: EmailVault, agent: Agent) -> dict[str, Any]:
    link = await crud.newest_link(session, agent.address)
    if link is None:
        return {"state": "none"}
    effective_at = service._aware(link.effective_at)
    if link.state == "active":
        state = "starts" if effective_at > service.utcnow() else "linked"
    else:
        state = _AGENT_STATES[link.state]
    return {
        "state": state, "account": await _account(session, vault, link.owner_pk),
        "effectiveAt": _stamp(effective_at), "words": words_for(link.agent_key),
    }


# --- the owner's side -----------------------------------------------------------


async def list_links(session: AsyncSession, owner: Owner) -> list[dict[str, Any]]:
    """The owner's links, each with who may message its agent (an agent
    with no setting yet lets anyone in, its own owner's agents too)."""
    now = service.utcnow()
    rows = await crud.links_for_owner(session, owner.id)
    policies = await inbound_crud.policies_for(session, [link.agent_address for link in rows])
    out = []
    for link in rows:
        row = policies.get(link.agent_address)
        out.append({**view(link, now), "policy": row.policy if row else "open",
                    "sameOwner": row.same_owner if row else True})
    return out


async def _owned(session: AsyncSession, owner: Owner, link_id: int) -> OwnerLink:
    link = await crud.link_for_owner(session, owner.id, link_id)
    if link is None or link.state == "started":
        raise PasskeyError(404, "no_link", "No such link.")
    return link


async def _signers(session: AsyncSession, owner: Owner, keys_hash: str) -> list[OwnerPasskey]:
    """Active passkeys listed in the key log entry *keys_hash*."""
    entry = await crud.key_log_entry(session, owner.id, keys_hash)
    if entry is None:
        return []
    listed = {k["id"] for k in parse_body(entry.body)["keys"]}
    return [p for p in await owner_crud.passkeys(session, owner.id) if p.did in listed]


async def _ask(
    session: AsyncSession, settings, owner: Owner, purpose: str, link: OwnerLink,
    body: dict[str, Any], screen: str, challenge: bytes,
) -> dict[str, Any]:
    asked = await _challenge(session, settings, owner, purpose, body, screen, challenge)
    return {"link": link.id, "body": canonical(body).decode(), "hash": object_hash(body), **asked}


async def _challenge(
    session: AsyncSession, settings, owner: Owner, purpose: str, body: dict[str, Any],
    screen: str, challenge: bytes,
) -> dict[str, Any]:
    """Store a challenge for *body* (its ``owner.keysHash`` names who may sign)."""
    signers = await _signers(session, owner, body["owner"]["keysHash"])
    if not signers:
        raise PasskeyError(409, "no_passkey", "None of your passkeys can approve this.")
    now = service.utcnow()
    text = canonical(body).decode()
    encoded = _b64u(challenge)
    # A link's challenge comes from its body alone, so asking again gives
    # the same one: renew that row rather than add a second. A set of one
    # link has the same challenge as the link alone; the newest ask decides
    # which route may use it.
    old = await owner_crud.find_challenge(session, owner.id, None, encoded)
    if old is not None:
        old.used_at, old.created_at, old.expires_at = None, now, now + CHALLENGE_TTL
        old.purpose, old.body, old.screen = purpose, text, screen
    else:
        await owner_crud.add_challenge(
            session, owner_pk=owner.id, purpose=purpose, challenge=encoded, now=now,
            expires_at=now + CHALLENGE_TTL, body=text, screen=screen,
        )
    await session.commit()
    return {
        "screen": screen, "challenge": encoded,
        "allowCredentials": [p.credential_id for p in signers], "rpId": settings.rp_id,
    }


async def approve_start(session: AsyncSession, settings, owner: Owner, link_id: int) -> dict[str, Any]:
    link = await _owned(session, owner, link_id)
    if link.state != "agent_signed":
        raise PasskeyError(409, "not_waiting", "This link isn't waiting for you.")
    body = parse_body(link.body)
    return await _ask(session, settings, owner, "link", link, body, link_screen(body),
                      link_challenge(body))


async def _assert(
    session: AsyncSession, settings, owner: Owner, purpose: str, assertion: dict[str, str]
):
    """Claim the challenge, then check the passkey signed it. Returns the
    challenge row, its body and the signing passkey (sign count updated)."""
    client = _unb64u(assertion["clientDataJSON"], "clientDataJSON")
    auth = _unb64u(assertion["authenticatorData"], "authenticatorData")
    sig = _unb64u(assertion["signature"], "signature")
    row = await _claim(session, owner, purpose, _client_challenge(client))
    await session.commit()  # used up, whatever happens next
    body = parse_body(row.body)
    signer = await owner_crud.passkey_by_credential(session, owner.id, assertion["credentialId"])
    allowed = {p.id for p in await _signers(session, owner, body["owner"]["keysHash"])}
    if signer is None or signer.id not in allowed:
        raise PasskeyError(400, "bad_signer", "That passkey can't approve this.")
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
        raise PasskeyError(400, "bad_passkey", str(exc)) from None
    signer.sign_count = count
    return row, body, signer


async def approve(
    session: AsyncSession, settings, owner: Owner, link_id: int, assertion: dict[str, str]
) -> dict[str, Any]:
    link = await _owned(session, owner, link_id)
    row, body, signer = await _assert(session, settings, owner, "link", assertion)
    if object_hash(body) != link.hash:
        await session.rollback()
        raise PasskeyError(409, "not_waiting", "This link isn't waiting for you.")
    now = service.utcnow()
    if not await crud.move_link(
        session, link.id, ("agent_signed",), state="active", owner_signer=signer.did,
        authenticator_data=assertion["authenticatorData"],
        client_data_json=assertion["clientDataJSON"], signature=assertion["signature"],
        screen=row.screen, approved_at=now,
    ):
        await session.rollback()
        raise PasskeyError(409, "not_waiting", "This link isn't waiting for you.")
    await _join_fleet(session, link, now)
    await owner_crud.audit(session, owner.id, "link_approved", {"link": link.id})
    await session.commit()
    await session.refresh(link)
    return view(link, now)


async def _join_fleet(session: AsyncSession, link: OwnerLink, now: datetime) -> None:
    from uam.relay.owners import policy  # policy imports this module

    await policy.join_fleet(session, link, now)


# --- a set of links, one passkey (P2d-4) ---------------------------------------


async def _waiting_set(session: AsyncSession, owner: Owner, ids: list[int]) -> list[OwnerLink]:
    found = []
    for link_id in ids:
        link = await _owned(session, owner, link_id)
        if link.state != "agent_signed":
            raise PasskeyError(409, "not_waiting", "One of these links isn't waiting for you.")
        found.append(link)
    return sorted(found, key=lambda link: link.agent_address)


async def approve_set_start(
    session: AsyncSession, settings, owner: Owner, ids: list[int]
) -> dict[str, Any]:
    """One challenge over several waiting links and one sentence naming them."""
    found = await _waiting_set(session, owner, ids)
    bodies = [parse_body(link.body) for link in found]
    keys_hashes = {body["owner"]["keysHash"] for body in bodies}
    if len(keys_hashes) != 1:
        raise PasskeyError(
            409, "approve_one_by_one",
            "Your passkeys changed while these were waiting. Approve them one by one.",
        )
    # What the challenge row keeps: the links, in screen order, and the
    # key log entry whose passkeys may sign.
    held = {
        "owner": {"keysHash": keys_hashes.pop()},
        "links": [link.id for link in found], "hashes": [link.hash for link in found],
    }
    asked = await _challenge(session, settings, owner, "links", held, links_screen(bodies),
                             links_challenge(bodies))
    return {
        "links": held["links"], "bodies": [link.body for link in found],
        "hashes": held["hashes"], **asked,
    }


async def approve_set(
    session: AsyncSession, settings, owner: Owner, assertion: dict[str, str],
    only: set[int] | None = None,
) -> dict[str, Any]:
    """Approve every link in the set, or none of them. *only*: the links
    this session may approve (a session opened from a request email)."""
    row, held, signer = await _assert(session, settings, owner, "links", assertion)
    if only is not None and not set(held["links"]) <= only:
        await session.rollback()
        raise PasskeyError(403, "not_yours", "This session can only approve its own request.")
    try:
        found = await _waiting_set(session, owner, held["links"])
    except PasskeyError:
        await session.rollback()
        raise PasskeyError(409, "not_waiting", "One of these links isn't waiting for you.") from None
    now = service.utcnow()
    kept = json.dumps(held["hashes"]) if len(found) > 1 else None
    for link in found:
        if not await crud.move_link(
            session, link.id, ("agent_signed",), state="active", owner_signer=signer.did,
            authenticator_data=assertion["authenticatorData"],
            client_data_json=assertion["clientDataJSON"], signature=assertion["signature"],
            screen=row.screen, approved_at=now, approval_set=kept,
        ):
            await session.rollback()
            raise PasskeyError(409, "not_waiting", "One of these links isn't waiting for you.")
        await _join_fleet(session, link, now)
        await owner_crud.audit(session, owner.id, "link_approved",
                               {"link": link.id, "set": len(found)})
    await session.commit()
    for link in found:
        await session.refresh(link)
    return {"links": [view(link, now) for link in found]}


async def cancel(session: AsyncSession, owner: Owner, link_id: int) -> dict[str, Any]:
    """End a link that hasn't started yet. No passkey: it only narrows."""
    link = await _owned(session, owner, link_id)
    now = service.utcnow()
    waiting = link.state == "agent_signed"
    pending = link.state == "active" and service._aware(link.effective_at) > now
    if not (waiting or pending) or not await crud.move_link(
        session, link.id, (link.state,), state="cancelled", live_for=None, ended_at=now
    ):
        raise PasskeyError(409, "not_cancellable", "Only a link that hasn't started can be cancelled.")
    await owner_crud.audit(session, owner.id, "link_cancelled", {"link": link.id, "by": "owner"})
    await session.commit()
    await session.refresh(link)
    return view(link, now)


def _unlink_body(settings, owner: Owner, head_hash: str, link: OwnerLink, reason: str) -> dict:
    return {
        "type": UNLINK, "v": 1,
        "owner": {"relay": settings.relay_domain, "ownerId": owner.owner_id, "keysHash": head_hash},
        "agent": link.agent_address, "agentKey": link.agent_key, "reason": reason,
        "validFrom": _stamp(service.utcnow()), "nonce": _nonce(),
    }


async def unlink_start(session: AsyncSession, settings, owner: Owner, link_id: int) -> dict[str, Any]:
    link = await _owned(session, owner, link_id)
    if link.state != "active":
        raise PasskeyError(409, "not_linked", "Only a linked agent can be unlinked.")
    head = await owner_crud.key_log_head(session, owner.id)
    body = _unlink_body(settings, owner, head.hash, link, "owner")
    return await _ask(session, settings, owner, "unlink", link, body, unlink_screen(body),
                      unlink_challenge(body))


async def _end(
    session: AsyncSession, link: OwnerLink, body: dict[str, Any], *, signer: str,
    set_by: str, assertion: dict[str, str] | None = None, screen: str | None = None,
    signature: str | None = None,
) -> None:
    now = service.utcnow()
    if not await crud.move_link(session, link.id, ("active",), state="unlinked", live_for=None,
                                ended_at=now):
        await session.rollback()
        raise PasskeyError(409, "not_linked", "Only a linked agent can be unlinked.")
    session.add(OwnerUnlink(
        link_pk=link.id, body=canonical(body).decode(), hash=object_hash(body),
        reason=body["reason"], signer=signer,
        authenticator_data=assertion["authenticatorData"] if assertion else None,
        client_data_json=assertion["clientDataJSON"] if assertion else None,
        signature=assertion["signature"] if assertion else signature,
        screen=screen, created_at=now,
    ))
    await crud.close_policy(session, link.agent_address, set_by, now)
    await owner_crud.audit(session, link.owner_pk, "link_unlinked",
                           {"link": link.id, "reason": body["reason"]})
    await session.commit()


async def unlink(
    session: AsyncSession, settings, owner: Owner, link_id: int, assertion: dict[str, str]
) -> dict[str, Any]:
    link = await _owned(session, owner, link_id)
    row, body, signer = await _assert(session, settings, owner, "unlink", assertion)
    if body["agent"] != link.agent_address or body["agentKey"] != link.agent_key:
        await session.rollback()
        raise PasskeyError(409, "not_linked", "Only a linked agent can be unlinked.")
    await _end(session, link, body, signer=signer.did, set_by="owner", assertion=assertion,
               screen=row.screen)
    await session.refresh(link)
    return view(link, service.utcnow())


async def admin_unlink(session: AsyncSession, settings, relay_key, link_id: int) -> dict[str, Any]:
    """The relay admin ends a link; the relay signs the unlink if it has a key."""
    link = await session.get(OwnerLink, link_id)
    if link is None:
        raise PasskeyError(404, "no_link", "No such link.")
    if link.state != "active":
        raise PasskeyError(409, "not_linked", "Only a linked agent can be unlinked.")
    owner = await session.get(Owner, link.owner_pk)
    head = await owner_crud.key_log_head(session, owner.id)
    body = _unlink_body(settings, owner, head.hash, link, "admin")
    signature = (
        sign_message(relay_sig_message(UNLINK, object_hash(body)), relay_key)
        if relay_key is not None else None
    )
    await _end(session, link, body, signer="relay", set_by="admin", signature=signature)
    await session.refresh(link)
    return view(link, service.utcnow())


async def make_private(
    session: AsyncSession, owner: Owner, link_id: int, private: bool
) -> dict[str, Any]:
    """Narrowing only: sharing a link again needs P2e's signed approval."""
    link = await _owned(session, owner, link_id)
    if not private:
        raise PasskeyError(409, "not_yet", "Sharing a private link again isn't available yet.")
    if link.state not in ("agent_signed", "active"):
        raise PasskeyError(409, "not_linked", "This link has ended.")
    link.private = True
    await owner_crud.audit(session, owner.id, "link_private", {"link": link.id})
    await session.commit()
    await session.refresh(link)
    return view(link, service.utcnow())

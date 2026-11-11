"""Who may message an agent, as its owner sets it (P2e-1, v2 §5.2).

Anyone (``open``) or Only my contacts (``contacts``), and whether the
owner's other agents get through (``same_owner``). Narrowing needs no
passkey. Widening (to Anyone, from a closed policy, or letting the owner's
own agents through again) needs the owner's passkey over a
``UamAgentPolicy``.

Choosing Only my contacts sets aside the contacts the agent had before
(``inbound_contacts`` rows an admin added in P1): none is kept unless the
owner keeps it, with a passkey, as a grant for that sender's address and
key and for this agent's key (DEC-006).
"""

from __future__ import annotations

import json
from datetime import timedelta
from typing import Any

from sqlalchemy import and_, exists, select
from sqlalchemy.ext.asyncio import AsyncSession

from uam.db.crud import inbound
from uam.db.crud import owner_links as link_crud
from uam.db.models import (
    AgentPolicyApproval,
    InboundContact,
    Owner,
    OwnerGrant,
    OwnerLink,
    RoutedMessage,
)
from uam.protocol.contacts import GRANT, POLICY, keep_screen, policy_screen
from uam.protocol.signed import canonical, object_hash, parse_body
from uam.relay.gate import _did
from uam.relay.owners import contacts, service
from uam.relay.owners.links import _nonce, _stamp
from uam.relay.owners.passkeys import PasskeyError

#: Strictest first: moving right widens.
_RANK = {"closed": 0, "contacts": 1, "open": 2}
#: A carried-over contact younger than this is warned about.
RECENT = timedelta(days=14)
#: Contacts one approval can keep.
MAX_KEEP = 64


async def _linked(session: AsyncSession, owner: Owner, link_id: int) -> OwnerLink:
    link = await link_crud.link_for_owner(session, owner.id, link_id)
    if link is None or link.state == "started":
        raise PasskeyError(404, "no_link", "No such link.")
    if link.state != "active":
        raise PasskeyError(409, "not_linked", "This agent isn't linked.")
    if service._aware(link.effective_at) > service.utcnow():
        raise PasskeyError(409, "not_started", "This link hasn't started yet.")
    return link


async def _current(session: AsyncSession, agent: str) -> tuple[str, bool]:
    row = await inbound.get_policy(session, agent)
    return (row.policy, row.same_owner) if row is not None else ("open", True)


def _widens(now: tuple[str, bool], policy: str, same_owner: bool) -> bool:
    return _RANK[policy] > _RANK[now[0]] or (same_owner and not now[1])


async def _two_way(session: AsyncSession, a: str, b: str) -> bool:
    def sent(frm: str, to: str):
        return exists().where(and_(RoutedMessage.from_addr == frm, RoutedMessage.to_addr == to))

    return bool(await session.scalar(select(and_(sent(a, b), sent(b, a)))))


async def _kept(session: AsyncSession, link: OwnerLink) -> dict[str, Any]:
    now = service.utcnow()
    out = {}
    for grant in await _agent_grants(session, link.owner_pk, now):
        if json.loads(grant.location_keys or "{}").get(link.agent_address) == link.agent_key:
            out[grant.subject_address] = grant
    return out


async def _agent_grants(session: AsyncSession, owner_pk: int, now) -> list[OwnerGrant]:
    return list((await session.execute(
        select(OwnerGrant).where(
            OwnerGrant.owner_pk == owner_pk, OwnerGrant.subject_kind == "agent",
            OwnerGrant.revoked_at.is_(None), OwnerGrant.valid_until > now,
        ).order_by(OwnerGrant.id)
    )).scalars())


async def _carried(session: AsyncSession, agent: str) -> list[InboundContact]:
    return [
        row for row in await inbound.list_contacts(session, agent)
        if row.state in ("allowed", "set_aside")
    ]


async def view(session: AsyncSession, link: OwnerLink) -> dict[str, Any]:
    policy, same_owner = await _current(session, link.agent_address)
    now = service.utcnow()
    kept = await _kept(session, link)
    carried = []
    for row in await _carried(session, link.agent_address):
        recent = service._aware(row.created_at) > now - RECENT
        two_way = await _two_way(session, link.agent_address, row.contact_address)
        carried.append({
            "address": row.contact_address, "since": _stamp(row.created_at),
            "recent": recent, "twoWay": two_way, "warn": recent or not two_way,
            "kept": row.contact_address in kept,
        })
    return {
        "link": link.id, "agent": link.agent_address, "policy": policy, "sameOwner": same_owner,
        "carriedOver": carried,
        "kept": [{"address": a, "until": _stamp(g.valid_until)} for a, g in sorted(kept.items())],
    }


async def read(session: AsyncSession, owner: Owner, link_id: int) -> dict[str, Any]:
    return await view(session, await _linked(session, owner, link_id))


async def _apply(session: AsyncSession, agent: str, policy: str, same_owner: bool) -> None:
    await inbound.set_owner_policy(session, agent, policy, same_owner)
    if policy == "contacts":
        await inbound.set_aside(session, agent)


async def narrow(
    session: AsyncSession, owner: Owner, link_id: int, policy: str, same_owner: bool
) -> dict[str, Any]:
    """Narrow who may message the agent. No passkey; widening is refused."""
    link = await _linked(session, owner, link_id)
    now = await _current(session, link.agent_address)
    if _widens(now, policy, same_owner):
        raise PasskeyError(409, "needs_passkey", "Letting more in needs your passkey.")
    await _apply(session, link.agent_address, policy, same_owner)
    await contacts.owner_crud.audit(session, owner.id, "policy_narrowed", {
        "link": link.id, "policy": policy, "sameOwner": same_owner,
    })
    await session.commit()
    return await view(session, link)


async def widen_start(
    session: AsyncSession, settings, owner: Owner, link_id: int, policy: str, same_owner: bool,
    credential_id: str | None,
) -> dict[str, Any]:
    link = await _linked(session, owner, link_id)
    keys_hash = await contacts._head(session, owner)
    signer = await contacts._signer(session, owner, keys_hash, credential_id)
    body = {
        "type": POLICY, "v": 1, "owner": contacts._owner_ref(settings, owner, keys_hash),
        "agent": link.agent_address, "agentKey": link.agent_key, "policy": policy,
        "sameOwner": same_owner, "validFrom": _stamp(service.utcnow()), "nonce": _nonce(),
    }
    held = {"owner": {"keysHash": keys_hash}, "link": link.id, "body": canonical(body).decode()}
    return await contacts._ask(session, settings, owner, "policy", held, [(POLICY, body)],
                               policy_screen(body), signer)


def _not_this_agent() -> PasskeyError:
    return PasskeyError(409, "not_this_agent", "That approval was for another agent.")


async def widen(
    session: AsyncSession, settings, owner: Owner, link_id: int, assertion: dict[str, str]
) -> dict[str, Any]:
    link = await _linked(session, owner, link_id)
    row, held, signer = await contacts._approved(session, settings, owner, "policy", assertion)
    body = parse_body(held["body"])
    if held["link"] != link.id or body["agentKey"] != link.agent_key:
        await session.rollback()
        raise _not_this_agent()
    await _apply(session, link.agent_address, body["policy"], body["sameOwner"])
    session.add(AgentPolicyApproval(
        owner_pk=owner.id, agent_address=link.agent_address, body=held["body"],
        hash=object_hash(body), **contacts._proof(row, signer, assertion),
    ))
    await contacts.owner_crud.audit(session, owner.id, "policy_widened", {
        "link": link.id, "policy": body["policy"], "sameOwner": body["sameOwner"],
    })
    await session.commit()
    return await view(session, link)


async def keep_start(
    session: AsyncSession, settings, owner: Owner, link_id: int, addresses: list[str],
    credential_id: str | None,
) -> dict[str, Any]:
    """Keep carried-over contacts: one grant each, for its address and key."""
    link = await _linked(session, owner, link_id)
    carried = {r.contact_address: r for r in await _carried(session, link.agent_address)}
    if not addresses or any(a not in carried for a in addresses):
        raise PasskeyError(409, "not_carried_over", "Only a contact this agent had can be kept.")
    keys_hash = await contacts._head(session, owner)
    signer = await contacts._signer(session, owner, keys_hash, credential_id)
    now = service.utcnow()
    grants = []
    for address in sorted(set(addresses)):
        key = _did(carried[address].contact_key)
        if key is None:
            raise PasskeyError(409, "not_carried_over", "That contact has no usable key.")
        grants.append(contacts._grant_body(
            settings, owner, signer.did, {"kind": "agent", "id": key, "address": address},
            "carried_over", now, locations=[link.agent_address],
        ))
    held = {"owner": {"keysHash": keys_hash}, "link": link.id,
            "grants": [canonical(g).decode() for g in grants]}
    return await contacts._ask(session, settings, owner, "keep", held,
                               [(GRANT, g) for g in grants],
                               keep_screen(grants, link.agent_address), signer)


async def keep(
    session: AsyncSession, settings, owner: Owner, link_id: int, assertion: dict[str, str]
) -> dict[str, Any]:
    link = await _linked(session, owner, link_id)
    row, held, signer = await contacts._approved(session, settings, owner, "keep", assertion)
    if held["link"] != link.id:
        await session.rollback()
        raise _not_this_agent()
    proof = contacts._proof(row, signer, assertion)
    for text in held["grants"]:
        grant = parse_body(text)
        subject = grant["credentialSubject"]
        session.add(contacts._grant_row(
            owner, grant, proof, subject_address=subject["address"], subject_key=subject["id"],
            location_keys=json.dumps({link.agent_address: link.agent_key}),
        ))
    await contacts.owner_crud.audit(session, owner.id, "contacts_kept", {
        "link": link.id, "count": len(held["grants"]),
    })
    await session.commit()
    return await view(session, link)


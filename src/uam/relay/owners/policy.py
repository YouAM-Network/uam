"""Who may message an agent, as its owner sets it (P2e-1, v2 §5.2).

Anyone (``open``) or Only my contacts (``contacts``), and whether the
owner's other agents get through (``same_owner``). Narrowing needs no
passkey. Widening (to Anyone, from a closed policy, or letting the owner's
own agents through again) needs the owner's passkey over a
``UamAgentPolicy``.

Several agents (or a fleet's) can be set at once (P2e-1b): narrowing needs
nothing and a request that would widen any of them is refused whole;
widening signs one ``UamAgentPolicy`` per agent under one sentence. An
agent that joins a fleet takes its setting if that only narrows.

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
    OwnerFleet,
    OwnerGrant,
    OwnerLink,
    RoutedMessage,
)
from uam.protocol.contacts import GRANT, POLICY, keep_screen, policies_screen, policy_screen
from uam.protocol.signed import canonical, object_hash, parse_body
from uam.relay.gate import _did
from uam.relay.owners import contacts, fleets, service
from uam.relay.owners.links import _nonce, _stamp
from uam.relay.owners.passkeys import PasskeyError

#: Strictest first: moving right widens.
_RANK = {"closed": 0, "contacts": 1, "open": 2}
#: A carried-over contact younger than this is warned about.
RECENT = timedelta(days=14)
#: Contacts one approval can keep.
MAX_KEEP = 64
#: Agents one request can set.
MAX_SET = 50


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



# --- several agents, or a fleet, at once (P2e-1b) -------------------------------


async def _targets(
    session: AsyncSession, owner: Owner, ids: list[int] | None, fleet_id: int | None
) -> tuple[list[OwnerLink], OwnerFleet | None]:
    """The links to set, by agent address: *ids*, or the fleet's in effect."""
    if fleet_id is not None:
        fleet = await fleets.get(session, owner, fleet_id)
        now = service.utcnow()
        links = [
            link for link in await fleets.members(session, fleet)
            if link.state == "active" and service._aware(link.effective_at) <= now
        ]
        if not links:
            raise PasskeyError(409, "no_agents", "No agent in this fleet is linked yet.")
        return links, fleet
    links = [await _linked(session, owner, link_id) for link_id in ids or []]
    return sorted(links, key=lambda link: link.agent_address), None


def _summary(links: list[OwnerLink], fleet: OwnerFleet | None, policy: str, same: bool) -> dict:
    return {"links": [link.id for link in links], "fleet": fleet.id if fleet else None,
            "policy": policy, "sameOwner": same}


async def narrow_many(
    session: AsyncSession, owner: Owner, ids: list[int] | None, fleet_id: int | None,
    policy: str, same_owner: bool,
) -> dict[str, Any]:
    """Narrow several agents with no passkey: all of them, or none if any would widen."""
    links, fleet = await _targets(session, owner, ids, fleet_id)
    for link in links:
        if _widens(await _current(session, link.agent_address), policy, same_owner):
            raise PasskeyError(409, "needs_passkey", "Letting more in needs your passkey.")
    for link in links:
        await _apply(session, link.agent_address, policy, same_owner)
    if fleet is not None:
        fleet.policy, fleet.same_owner = policy, same_owner
    await contacts.owner_crud.audit(session, owner.id, "policy_narrowed",
                                    _summary(links, fleet, policy, same_owner))
    await session.commit()
    return {"policies": [await view(session, link) for link in links]}


async def widen_many_start(
    session: AsyncSession, settings, owner: Owner, ids: list[int] | None, fleet_id: int | None,
    policy: str, same_owner: bool, credential_id: str | None,
) -> dict[str, Any]:
    links, fleet = await _targets(session, owner, ids, fleet_id)
    keys_hash = await contacts._head(session, owner)
    signer = await contacts._signer(session, owner, keys_hash, credential_id)
    owner_ref = contacts._owner_ref(settings, owner, keys_hash)
    stamp = _stamp(service.utcnow())
    bodies = [{
        "type": POLICY, "v": 1, "owner": owner_ref, "agent": link.agent_address,
        "agentKey": link.agent_key, "policy": policy, "sameOwner": same_owner,
        "validFrom": stamp, "nonce": _nonce(),
    } for link in links]
    held = {
        "owner": {"keysHash": keys_hash}, "links": [link.id for link in links],
        "bodies": [canonical(body).decode() for body in bodies],
        **({"fleet": fleet.id} if fleet else {}),  # canonical JSON has no null
    }
    screen = policies_screen(bodies, fleet.name if fleet else None)
    return await contacts._ask(session, settings, owner, "policies", held,
                               [(POLICY, body) for body in bodies], screen, signer)


async def widen_many(
    session: AsyncSession, settings, owner: Owner, assertion: dict[str, str]
) -> dict[str, Any]:
    """Apply every signed body, or none: each agent must still be linked, with that key."""
    row, held, signer = await contacts._approved(session, settings, owner, "policies", assertion)
    bodies = [parse_body(text) for text in held["bodies"]]
    links = []
    for link_id, body in zip(held["links"], bodies, strict=True):
        try:
            link = await _linked(session, owner, link_id)
        except PasskeyError:
            await session.rollback()
            raise PasskeyError(409, "not_linked", "One of these agents isn't linked now.") from None
        if body["agentKey"] != link.agent_key:
            await session.rollback()
            raise _not_this_agent()
        links.append(link)
    hashes = [object_hash(body) for body in bodies]
    kept = json.dumps(hashes) if len(bodies) > 1 else None
    proof = contacts._proof(row, signer, assertion)
    for link, body, text, digest in zip(links, bodies, held["bodies"], hashes, strict=True):
        await _apply(session, link.agent_address, body["policy"], body["sameOwner"])
        session.add(AgentPolicyApproval(
            owner_pk=owner.id, agent_address=link.agent_address, body=text, hash=digest,
            approval_set=kept, **proof,
        ))
    first = bodies[0]
    fleet = await session.get(OwnerFleet, held["fleet"]) if "fleet" in held else None
    if fleet is not None and fleet.owner_pk == owner.id:
        fleet.policy, fleet.same_owner = first["policy"], first["sameOwner"]
    await contacts.owner_crud.audit(session, owner.id, "policy_widened",
                                    _summary(links, fleet, first["policy"], first["sameOwner"]))
    await session.commit()
    return {"policies": [await view(session, link) for link in links]}


async def join_fleet(session: AsyncSession, link: OwnerLink, now) -> None:
    """A link just approved takes its fleet's setting, if it's in effect now
    and the setting only lets fewer in. Called before the approval commits."""
    if link.fleet_id is None or service._aware(link.effective_at) > now:
        return
    fleet = await session.get(OwnerFleet, link.fleet_id)
    if fleet is None or fleet.policy is None:
        return
    same = bool(fleet.same_owner)
    if not _widens(await _current(session, link.agent_address), fleet.policy, same):
        await _apply(session, link.agent_address, fleet.policy, same)

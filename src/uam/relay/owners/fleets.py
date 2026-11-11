"""Fleets: named groups of one owner's agents (P2e-1b, UAM-17).

A link is in one fleet at most. A code for several agents can name a fleet
(the links made from it join), and an owner can make a fleet from chosen
agents, move agents in or out, rename it and ungroup it.

Grouping grants nothing: nothing here changes who may message an agent, so
nothing here needs a passkey. A fleet's *setting* is set through
``policy`` (several agents at once), which also stores it on the fleet.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from uam.db.crud import owner_links as link_crud
from uam.db.crud import owners as owner_crud
from uam.db.models import Owner, OwnerCode, OwnerFleet, OwnerLink
from uam.relay.owners.passkeys import PasskeyError

#: A fleet's name: one short line.
MAX_NAME = 40


def tidy(name: str) -> str:
    """The name as stored: runs of spaces become one, ends trimmed."""
    return " ".join(name.split())


def name_key(name: str) -> str:
    return tidy(name).casefold()


def _no_fleet() -> PasskeyError:
    return PasskeyError(404, "no_fleet", "No such fleet.")


def _taken() -> PasskeyError:
    return PasskeyError(409, "name_taken", "You already have a fleet with that name.")


async def get(session: AsyncSession, owner: Owner, fleet_id: int) -> OwnerFleet:
    fleet = await session.get(OwnerFleet, fleet_id)
    if fleet is None or fleet.owner_pk != owner.id:
        raise _no_fleet()
    return fleet


async def _by_name(session: AsyncSession, owner: Owner, name: str) -> OwnerFleet | None:
    return await session.scalar(select(OwnerFleet).where(
        OwnerFleet.owner_pk == owner.id, OwnerFleet.name_key == name_key(name),
    ))


async def members(session: AsyncSession, fleet: OwnerFleet) -> list[OwnerLink]:
    """The fleet's live links the agents have signed, by agent address (an
    ended link has left; one not yet signed isn't the owner's to see)."""
    return list((await session.execute(
        select(OwnerLink)
        .where(
            OwnerLink.fleet_id == fleet.id, OwnerLink.live_for.is_not(None),
            OwnerLink.agent_signature.is_not(None),
        )
        .order_by(OwnerLink.agent_address)
    )).scalars())


async def view(session: AsyncSession, fleet: OwnerFleet) -> dict[str, Any]:
    return {
        "id": fleet.id, "name": fleet.name, "policy": fleet.policy,
        "sameOwner": fleet.same_owner,
        "links": [link.id for link in await members(session, fleet)],
    }


async def list_fleets(session: AsyncSession, owner: Owner) -> dict[str, Any]:
    fleets = (await session.execute(
        select(OwnerFleet).where(OwnerFleet.owner_pk == owner.id).order_by(OwnerFleet.name_key)
    )).scalars()
    return {"fleets": [await view(session, fleet) for fleet in fleets]}


async def _new(session: AsyncSession, owner: Owner, name: str) -> OwnerFleet:
    if await _by_name(session, owner, name) is not None:
        raise _taken()
    fleet = OwnerFleet(owner_pk=owner.id, name=tidy(name), name_key=name_key(name))
    session.add(fleet)
    await session.flush()
    return fleet


async def find_or_make(session: AsyncSession, owner: Owner, name: str) -> OwnerFleet:
    """The owner's fleet with this name, made if it isn't there (for a code)."""
    return await _by_name(session, owner, name) or await _new(session, owner, name)


async def _live_links(session: AsyncSession, owner: Owner, ids: list[int]) -> list[OwnerLink]:
    found = []
    for link_id in ids:
        link = await link_crud.link_for_owner(session, owner.id, link_id)
        if link is None or link.live_for is None or link.agent_signature is None:
            raise PasskeyError(404, "no_link", "No such link.")
        found.append(link)
    return found


async def _put(session: AsyncSession, links: list[OwnerLink], fleet_id: int | None) -> None:
    if links:
        await session.execute(
            update(OwnerLink).where(OwnerLink.id.in_([link.id for link in links]))
            .values(fleet_id=fleet_id)
        )


async def make(session: AsyncSession, owner: Owner, name: str, ids: list[int]) -> dict[str, Any]:
    """A fleet of the chosen agents, taken out of any fleet they were in."""
    links = await _live_links(session, owner, ids)
    fleet = await _new(session, owner, name)
    await _put(session, links, fleet.id)
    await owner_crud.audit(session, owner.id, "fleet_made", {"fleet": fleet.id, "links": ids})
    await session.commit()
    return await view(session, fleet)


async def move(
    session: AsyncSession, owner: Owner, ids: list[int], fleet_id: int | None
) -> dict[str, Any]:
    """Move links into a fleet, or (*fleet_id* None) out of any."""
    links = await _live_links(session, owner, ids)
    fleet = await get(session, owner, fleet_id) if fleet_id is not None else None
    await _put(session, links, fleet_id)
    await owner_crud.audit(session, owner.id, "fleet_moved", {"fleet": fleet_id, "links": ids})
    await session.commit()
    return await list_fleets(session, owner) if fleet is None else await view(session, fleet)


async def rename(session: AsyncSession, owner: Owner, fleet_id: int, name: str) -> dict[str, Any]:
    fleet = await get(session, owner, fleet_id)
    other = await _by_name(session, owner, name)
    if other is not None and other.id != fleet.id:
        raise _taken()
    fleet.name, fleet.name_key = tidy(name), name_key(name)
    await owner_crud.audit(session, owner.id, "fleet_renamed", {"fleet": fleet.id})
    await session.commit()
    return await view(session, fleet)


async def ungroup(session: AsyncSession, owner: Owner, fleet_id: int) -> dict[str, Any]:
    """Delete the fleet. Its agents stay linked, with the settings they have."""
    fleet = await get(session, owner, fleet_id)
    # Explicit, so it doesn't rest on the database's ON DELETE SET NULL
    # (SQLite only honours it with foreign keys on).
    for table in (OwnerLink, OwnerCode):
        await session.execute(update(table).where(table.fleet_id == fleet.id).values(fleet_id=None))
    await session.delete(fleet)
    await owner_crud.audit(session, owner.id, "fleet_ungrouped", {"fleet": fleet_id})
    await session.commit()
    return await list_fleets(session, owner)

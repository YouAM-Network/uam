"""CRUD for an agent's inbound policy and contacts (the delivery gate, P1).

Every change bumps the policy row's ``revision`` (creating an ``open`` row
if the agent had none), so a writer can tell whether it read the latest.
Functions flush and commit their own changes.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from uam.db.models import InboundContact, InboundPolicy


class RevisionMismatch(Exception):
    """The caller's revision isn't the current one."""

    def __init__(self, current: int) -> None:
        super().__init__(f"current revision is {current}")
        self.current = current


async def get_policy(session: AsyncSession, agent: str) -> InboundPolicy | None:
    return await session.get(InboundPolicy, agent)


async def list_contacts(
    session: AsyncSession, agent: str, *, limit: int = 500, offset: int = 0
) -> list[InboundContact]:
    stmt = (
        select(InboundContact)
        .where(InboundContact.agent_address == agent)
        .order_by(InboundContact.contact_address)
        .limit(limit)
        .offset(offset)
    )
    return list((await session.execute(stmt)).scalars())


async def _bump(session: AsyncSession, agent: str, set_by: str) -> InboundPolicy:
    row = await session.get(InboundPolicy, agent)
    if row is None:
        row = InboundPolicy(agent_address=agent, policy="open", revision=0, set_by=set_by)
        session.add(row)
    row.revision += 1
    row.updated_at = datetime.now(timezone.utc)
    return row


async def set_policy(
    session: AsyncSession, agent: str, policy: str, *, expected_revision: int, set_by: str
) -> int:
    """Set *agent*'s policy if *expected_revision* is current; return the new one."""
    row = await session.get(InboundPolicy, agent)
    current = row.revision if row is not None else 0
    if expected_revision != current:
        raise RevisionMismatch(current)
    row = await _bump(session, agent, set_by)
    row.policy = policy
    row.set_by = set_by
    await session.commit()
    return row.revision


async def put_contact(
    session: AsyncSession, agent: str, contact: str, *, key: str, state: str, source: str
) -> int:
    """Add or change one contact row; return the new revision."""
    row = await session.scalar(
        select(InboundContact).where(
            InboundContact.agent_address == agent,
            InboundContact.contact_address == contact,
        )
    )
    now = datetime.now(timezone.utc)
    if row is None:
        session.add(InboundContact(
            agent_address=agent, contact_address=contact, contact_key=key,
            state=state, source=source,
        ))
    else:
        row.contact_key = key
        row.state = state
        row.source = source
        row.updated_at = now
    policy = await _bump(session, agent, source)
    await session.commit()
    return policy.revision


async def delete_contact(session: AsyncSession, agent: str, contact: str) -> int | None:
    """Remove one contact row; return the new revision, or None if there was none."""
    row = await session.scalar(
        select(InboundContact).where(
            InboundContact.agent_address == agent,
            InboundContact.contact_address == contact,
        )
    )
    if row is None:
        return None
    await session.delete(row)
    policy = await _bump(session, agent, "admin")
    await session.commit()
    return policy.revision


async def set_owner_policy(
    session: AsyncSession, agent: str, policy: str, same_owner: bool
) -> InboundPolicy:
    """The owner's choice for *agent* (P2e). Flushes; the caller commits it
    with whatever approves it."""
    row = await _bump(session, agent, "owner")
    row.policy = policy
    row.same_owner = same_owner
    row.set_by = "owner"
    await session.flush()
    return row


async def set_aside(session: AsyncSession, agent: str) -> None:
    """Contacts *agent* had before its owner chose Only my contacts stop
    counting; the owner keeps any with a passkey (P2e). Flushes."""
    await session.execute(
        update(InboundContact)
        .where(InboundContact.agent_address == agent, InboundContact.state == "allowed")
        .values(state="set_aside", updated_at=datetime.now(timezone.utc))
    )
    await session.flush()

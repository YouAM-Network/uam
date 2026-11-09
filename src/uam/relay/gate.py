"""The delivery gate: who may deliver to an agent with an inbound policy.

An agent with no row in ``inbound_policies`` (every agent until owners can
set one) or with policy ``open`` takes mail from anyone, as before. Under
``contacts`` or ``closed`` only senders with an ``allowed`` row in
``inbound_contacts`` get through, and only when they signed with the key
on that row. Everything else is *pending*: the relay answers
``"pending"`` and keeps nothing (see specs/P1.md).

The one exception is a receipt whose ``reply_to`` names a message the
relay routed from the recipient to this sender: the recipient asked for it.

:func:`recipient_gate` only reads. Callers run it before any write, so a
pending answer costs the same and leaves nothing behind whatever the
reason was.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy import update as sa_update
from sqlalchemy.ext.asyncio import AsyncSession

from uam.db.models import InboundContact, InboundPolicy, Message, RoutedMessage

logger = logging.getLogger(__name__)

#: Message.status for stored mail the gate held back on the way out.
WITHHELD = "withheld"

GATED_POLICIES = frozenset({"contacts", "closed"})
POLICIES = frozenset({"open"}) | GATED_POLICIES
_RECEIPT_PREFIX = "receipt."


def _aware(value: datetime) -> datetime:
    # SQLite hands back naive datetimes for timezone-aware columns.
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


async def recipient_gate(
    session: AsyncSession,
    *,
    recipient: str,
    sender: str,
    message_type: str,
    sender_key: str | None,
    reply_to: str | None = None,
) -> bool:
    """True when *sender*'s message may be delivered to *recipient*.

    *sender_key* is the base64 key that verified the envelope's signature;
    ``None`` at egress, where the key was already checked on the way in.
    """
    policy = await session.scalar(
        select(InboundPolicy.policy).where(InboundPolicy.agent_address == recipient)
    )
    if policy not in GATED_POLICIES:
        return True

    row = await session.scalar(
        select(InboundContact).where(
            InboundContact.agent_address == recipient,
            InboundContact.contact_address == sender,
        )
    )
    if row is not None and row.state == "blocked":
        return False
    if (
        row is not None
        and row.state == "allowed"
        and (row.expires_at is None or _aware(row.expires_at) > datetime.now(timezone.utc))
    ):
        return sender_key is None or row.contact_key == sender_key

    if message_type.startswith(_RECEIPT_PREFIX) and reply_to:
        routed = await session.scalar(
            select(RoutedMessage.message_id).where(
                RoutedMessage.message_id == reply_to,
                RoutedMessage.from_addr == recipient,
                RoutedMessage.to_addr == sender,
            )
        )
        return routed is not None
    return False


async def is_gated(session: AsyncSession, recipient: str) -> bool:
    policy = await session.scalar(
        select(InboundPolicy.policy).where(InboundPolicy.agent_address == recipient)
    )
    return policy in GATED_POLICIES


async def still_allowed(session: AsyncSession, recipient: str, envelope: dict) -> bool:
    """The gate again, for a message already accepted (egress, webhook retries).

    Mail stored before the recipient was gated, or before its sender was
    blocked, must not get out now.
    """
    return await recipient_gate(
        session,
        recipient=recipient,
        sender=str(envelope.get("from", "")),
        message_type=str(envelope.get("type", "")),
        sender_key=None,
        reply_to=envelope.get("reply_to"),
    )


async def release(session: AsyncSession, recipient: str, stored: list[Message]) -> list[Message]:
    """The stored messages *recipient* may have now.

    The rest are marked ``withheld`` (committed), so they stay on the relay
    until retention removes them but never fill another inbox page.
    """
    if not stored or not await is_gated(session, recipient):
        return stored
    keep: list[Message] = []
    held: list[int] = []
    for msg in stored:
        if await still_allowed(session, recipient, json.loads(msg.envelope)):
            keep.append(msg)
        else:
            held.append(msg.id)  # type: ignore[arg-type]
    if held:
        await session.execute(
            sa_update(Message).where(Message.id.in_(held)).values(status=WITHHELD)  # type: ignore[union-attr]
        )
        await session.commit()
        logger.info("Withheld %d stored messages for %s (inbound gate)", len(held), recipient)
    return keep

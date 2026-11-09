"""The relay's delivery checks, in one place for every ingress path.

REST ``/send``, the WebSocket loop, federation ``/deliver`` and the demo
widget's ``/demo/send`` each call :func:`authorize_delivery` once the
sender is known to be who the envelope says (a bearer token matching
``from``; for federation, a verified envelope signature) and before
anything is stored or routed. Callers that record the message id run it
in the same transaction as that insert and roll back when it refuses, so
a refused message is never remembered as seen and the sender can send it
again later.

Checks, in order:

0. Message type: one the protocol defines (``MessageType``). Any other is
   logged and delivered, or refused when ``UAM_UNKNOWN_MESSAGE_TYPES``
   is ``reject``.
1. Sender blocklist (SPAM-01), exact address or ``*::domain``.
2. Expiry (MSG-04): an ``expires`` already past (with clock-skew grace).
3. Recipient: a local agent, or an address federation can reach.
4. Reputation floor (SPAM-06) and sender rate limit (SPAM-04), adaptive
   by reputation tier; allowlisted senders get the full rate and no floor.
5. Sender-domain rate limit (SPAM-03), this relay's own domain exempt.
   Skipped for federated mail: the per-source-relay limit (FED-06) in
   federation ``/deliver`` already caps the sender's domain.
6. Recipient rate limit (RELAY-05).

:func:`refuse_early` repeats the blocklist, reputation floor and sender
limit, without taking a rate-limit slot, so REST and the WebSocket loop
can turn those senders away before parsing or touching the database.
:func:`charge_duplicate` takes the slot for a message already seen, which
never reaches :func:`authorize_delivery`.

Receipts (the three ``receipt.*`` types) skip 4-6. Instead, a receipt is *bound* when its
signed ``reply_to`` names a message this relay routed the other way
(``crud/routed.py``, at most 3 receipts per message), and goes through
as before. Any other receipt takes one slot in a small per-sender
bucket (``receipt_limiter``); past it the receipt is accepted but not
delivered (``Clearance.deliver`` is False), never an error, so SDKs
that send receipts without ``reply_to`` see no failures. Callers roll
back rather than commit such a receipt, so it leaves no row behind.

Every other message that passes is recorded as routed, in the caller's
transaction, so receipts about it can be bound.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from uam.db.crud.agents import get_agent_by_address
from uam.db.crud.routed import claim_receipt, record_routed
from uam.protocol import MessageEnvelope, MessageType
from uam.relay.gate import recipient_gate

logger = logging.getLogger(__name__)

_KNOWN_TYPES = frozenset(t.value for t in MessageType)
_RECEIPT_TYPES = frozenset(
    {
        MessageType.RECEIPT_DELIVERED.value,
        MessageType.RECEIPT_READ.value,
        MessageType.RECEIPT_FAILED.value,
    }
)

# Grace period for clock skew when checking expiry (seconds)
EXPIRY_GRACE_SECONDS = 30


class DeliveryDenied(Exception):
    """The relay will not take this message.

    ``status`` is the HTTP status for REST and federation; ``code`` is the
    WebSocket ``error`` value; ``detail`` is shown to the sender on both.
    """

    def __init__(self, status: int, code: str, detail: str) -> None:
        super().__init__(detail)
        self.status = status
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Clearance:
    """What a caller needs from the checks to route the message.

    ``deliver`` False means: accept it (a receipt past its bucket) but do
    not deliver or store it.
    """

    expires_at: datetime | None
    deliver: bool = True


def parse_expires(expires: str | None) -> datetime | None:
    """ISO 8601 ``expires`` to a datetime in UTC; malformed means no expiry."""
    if expires is None:
        return None
    try:
        parsed = datetime.fromisoformat(expires.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def is_receipt(message_type: Any) -> bool:
    """True for the receipt types the protocol defines, and no others."""
    return isinstance(message_type, str) and message_type in _RECEIPT_TYPES


def _domain(address: str) -> str:
    return address.split("::", 1)[1] if "::" in address else ""


def goes_to_peer(state: Any, address: str) -> bool:
    """True if mail for *address* leaves this relay through federation."""
    return (
        _domain(address) not in ("", state.settings.relay_domain)
        and state.settings.federation_enabled
        and getattr(state, "federation_service", None) is not None
    )


def _send_limit(state: Any, sender: str) -> int | None:
    """Sender rate limit: ``None`` is the limiter's default (full) rate.

    A score below the lowest tier (20) gives a limit of 0 (SPAM-06).
    """
    if state.spam_filter.is_allowed(sender):
        return None
    return state.reputation_manager.get_send_limit(sender)


async def refuse_early(state: Any, sender: str, *, receipt: bool) -> None:
    """Refuse *sender* now if the delivery checks are bound to.

    Costs no database work and takes no rate-limit slot:
    :func:`authorize_delivery` still takes the slot, once the message is
    known not to be a duplicate.  Raises :class:`DeliveryDenied`.
    """
    if state.spam_filter.is_blocked(sender):
        raise DeliveryDenied(403, "blocked", "Sender is blocked")
    if receipt:
        return
    send_limit = _send_limit(state, sender)
    if send_limit == 0:
        raise DeliveryDenied(403, "reputation_blocked", "Sender reputation too low")
    if await state.sender_limiter.remaining(sender, limit=send_limit) == 0:
        raise DeliveryDenied(429, "rate_limited", "Sender rate limit exceeded")


async def charge_duplicate(state: Any, sender: str, *, receipt: bool) -> None:
    """Take *sender*'s rate-limit slot for a message already seen.

    A duplicate is still accepted idempotently, but it costs the relay the
    same parsing and lookups as a new message.  Raises :class:`DeliveryDenied`.
    """
    if receipt:
        return
    send_limit = _send_limit(state, sender)
    if not await state.sender_limiter.check(sender, limit=send_limit):
        raise DeliveryDenied(429, "rate_limited", "Sender rate limit exceeded")


async def held_back(
    state: Any,
    envelope: MessageEnvelope,
    session: AsyncSession,
    *,
    sender_key: str,
) -> bool:
    """True when the recipient's gate holds this message back (``pending``).

    Run after the signature check (so a bad signature is refused the same
    way for every recipient) and before any write. A held-back message
    takes a slot in the sender's pending bucket, never the recipient's.
    Raises :class:`DeliveryDenied` when that bucket is full. Mail for a
    peer relay is gated there, not here.
    """
    if goes_to_peer(state, envelope.to_address):
        return False
    if await recipient_gate(
        session,
        recipient=envelope.to_address,
        sender=envelope.from_address,
        message_type=envelope.type,
        sender_key=sender_key,
        reply_to=envelope.reply_to,
    ):
        return False
    if not await state.pending_limiter.check(envelope.from_address):
        raise DeliveryDenied(429, "rate_limited", "Sender rate limit exceeded")
    return True


async def authorize_delivery(
    state: Any,
    envelope: MessageEnvelope,
    session: AsyncSession,
    *,
    federated: bool = False,
) -> Clearance:
    """Run the delivery checks for *envelope* against the relay's state.

    *state* is ``app.state``; *session* carries the caller's delivery
    transaction (rows are flushed, never committed here); *federated*
    marks mail from a peer relay. Raises :class:`DeliveryDenied` on
    refusal.
    """
    sender = envelope.from_address

    if envelope.type not in _KNOWN_TYPES:
        if state.settings.unknown_message_types == "reject":
            raise DeliveryDenied(
                400, "unknown_type", f"Unknown message type: {envelope.type!r}"
            )
        logger.warning(
            "Unknown message type %r from %s (delivered; set "
            "UAM_UNKNOWN_MESSAGE_TYPES=reject to refuse)",
            envelope.type,
            sender,
        )

    spam_filter = state.spam_filter
    if spam_filter.is_blocked(sender):
        raise DeliveryDenied(403, "blocked", "Sender is blocked")

    expires_at = parse_expires(envelope.expires)
    if expires_at is not None and (
        expires_at + timedelta(seconds=EXPIRY_GRACE_SECONDS) < datetime.now(timezone.utc)
    ):
        raise DeliveryDenied(400, "expired", "Message has expired")

    if not goes_to_peer(state, envelope.to_address):
        if await get_agent_by_address(session, envelope.to_address) is None:
            raise DeliveryDenied(
                404, "unknown_recipient", f"No such agent: {envelope.to_address}"
            )

    if is_receipt(envelope.type):
        if envelope.reply_to and await claim_receipt(
            session, envelope.reply_to, sender, envelope.to_address
        ):
            return Clearance(expires_at=expires_at)
        deliver = await state.receipt_limiter.check(sender)
        return Clearance(expires_at=expires_at, deliver=deliver)

    is_allowlisted = spam_filter.is_allowed(sender)
    send_limit = _send_limit(state, sender)
    if send_limit == 0:
        raise DeliveryDenied(403, "reputation_blocked", "Sender reputation too low")
    if not await state.sender_limiter.check(sender, limit=send_limit):
        raise DeliveryDenied(429, "rate_limited", "Sender rate limit exceeded")

    sender_domain = _domain(sender)
    if (
        not federated
        and sender_domain
        and sender_domain != state.settings.relay_domain
        and not is_allowlisted
    ):
        if not await state.domain_limiter.check(sender_domain):
            raise DeliveryDenied(429, "rate_limited", "Domain rate limit exceeded")

    if not await state.recipient_limiter.check(envelope.to_address):
        raise DeliveryDenied(
            429, "rate_limited", "Recipient rate limit exceeded (100/min)"
        )

    await record_routed(session, envelope.message_id, sender, envelope.to_address)
    return Clearance(expires_at=expires_at)

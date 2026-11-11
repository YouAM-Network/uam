"""Agents ask for an owner by email (P2s-3, DEC-009, spec P2 §4.3).

An agent asks an email address to own it. The address gets a link whose
token sits in the URL fragment, so it never reaches a server log and a
mail scanner fetching the page does nothing. Opening it on the owner page
makes the account if there is none, with a session that can only finish
this request. The owner accepts, the relay builds the link body, the agent
signs it (its SDK does that without asking: asking was its consent), and
the owner approves with a passkey.

The agent's answer is the same whether or not the address has an account,
and whether or not an email went out. Emails are few: 3 asks a day per
agent, 10 an hour per client address (at the route), and per address,
across all agents, 1 email an hour and 3 a day, under a relay-wide daily
cap. Over a limit the request is still recorded (an account sees it on its
page), but no email is sent.

A new agent (registered within the hour, never owned) asks to be set up
and is linked at once. Any other asks to be linked, and its link starts
72 hours after it signs, so whoever runs it can cancel. An agent that
already has an owner can't ask: only that owner can unlink it.
"""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from uam.db.crud import owner_links as link_crud
from uam.db.crud import owner_requests as crud
from uam.db.crud import owners as owner_crud
from uam.db.models import Agent, Owner, OwnerLink, OwnerRequest
from uam.protocol.links import words_for
from uam.protocol.signed import parse_body
from uam.relay.owners import links, service
from uam.relay.owners.crypto import EmailVault, new_token
from uam.relay.owners.crypto import token_hash as session_token_hash
from uam.relay.owners.passkeys import PasskeyError

log = logging.getLogger("uam.relay.owners")

REQUEST_TTL = timedelta(days=7)
#: An agent this new that has never had an owner is set up, not linked.
NEW_AGENT = timedelta(hours=1)
ASKS_PER_AGENT_DAY = 3
EMAILS_PER_ADDRESS_HOUR = 1
EMAILS_PER_ADDRESS_DAY = 3
#: A body older than this is built again before the agent sees it.
OFFER_FRESH = timedelta(minutes=5)

REPLY = "If that address can take requests, a confirmation is on its way."

#: Where a request email goes: (email, message). P2g sends a real email;
#: the message has ``agent``, ``words``, ``via``, ``expiresAt``,
#: ``hasAccount``, ``url`` and ``neverUrl``, and never text the agent wrote.
RequestSink = Callable[[str, dict[str, Any]], None]

#: Request states that are over.
ENDED = ("approved", "declined", "expired", "cancelled")
#: What the owner still has to act on.
WAITING = ("open", "waiting_for_agent", "waiting_for_you")


def log_sink(email: str, message: dict[str, Any]) -> None:
    """UAM_OWNER_CODES_TO_LOG: the link, never the email."""
    log.warning("owner request from %s: %s", message["agent"], message["url"])


def drop_sink(email: str, message: dict[str, Any]) -> None:
    log.debug("owner request from %s: no email sent, owner email arrives in P2g",
              message["agent"])


def _token_hash(token: str) -> str:
    return hashlib.sha256(b"UAM-OWNER-REQUEST-v1\n" + token.encode()).hexdigest()


def state_of(row: OwnerRequest, link: OwnerLink | None, now: datetime) -> str:
    """Where a request stands: its own state, or once accepted its link's."""
    if row.state in ENDED:
        return row.state
    if service._aware(row.expires_at) <= now:
        return "expired"
    if row.state == "open" or link is None:
        return "open"
    return {
        "started": "waiting_for_agent", "agent_signed": "waiting_for_you", "active": "approved",
    }.get(link.state, "cancelled")


async def _link(session: AsyncSession, row: OwnerRequest) -> OwnerLink | None:
    return await session.get(OwnerLink, row.link_id) if row.link_id else None


async def view(session: AsyncSession, row: OwnerRequest, now: datetime) -> dict[str, Any]:
    link = await _link(session, row)
    agent = await session.get(Agent, row.agent_address)
    key = link.agent_key if link else links.agent_key_of(agent)
    return {
        "id": row.id, "agent": row.agent_address, "words": words_for(key), "via": row.via,
        "state": state_of(row, link, now), "link": row.link_id,
        "expiresAt": links._stamp(row.expires_at), "createdAt": links._stamp(row.created_at),
    }


async def _close(session: AsyncSession, row: OwnerRequest, state: str, now: datetime) -> None:
    """End a request; a link it started that isn't approved ends with it."""
    link = await _link(session, row)
    if link is not None and link.state in ("started", "agent_signed"):
        await link_crud.move_link(session, link.id, (link.state,), state="cancelled",
                                  live_for=None, ended_at=now)
    row.state, row.live_for, row.ended_at = state, None, now


async def _settle(session: AsyncSession, row: OwnerRequest, now: datetime) -> str:
    """Write down a request's state if it has ended on its own (approved,
    expired, or its link cancelled); returns the state."""
    state = state_of(row, await _link(session, row), now)
    if state in ENDED and row.live_for is not None:
        row.state, row.live_for, row.ended_at = state, None, now
    return state


# --- the agent asks -------------------------------------------------------------


async def ask(
    session: AsyncSession, settings, vault: EmailVault, agent: Agent, email: str,
    sink: RequestSink,
) -> dict[str, Any]:
    """Record the agent's request and email it if the limits allow."""
    now = service.utcnow()
    address = agent.address
    mine = await crud.live_request(session, address)
    if mine is not None and await _settle(session, mine, now) in ENDED:
        mine = None
    live = await link_crud.live_link(session, address)
    if live is not None and (mine is None or live.id != mine.link_id) and live.state != "started":
        await session.rollback()
        raise PasskeyError(
            409, "has_owner",
            "This agent already has an owner, or is waiting for one. Only that owner can "
            "unlink it.",
        )
    if await crud.asked_since(session, address, now - timedelta(days=1)) >= ASKS_PER_AGENT_DAY:
        await session.rollback()
        raise PasskeyError(429, "too_many", "This agent has asked three times today. "
                           "Try again tomorrow.")
    if mine is not None:  # a new request replaces the old one
        await _close(session, mine, "cancelled", now)
    if live is not None and live.state == "started":  # an unsigned code link gives way
        await link_crud.move_link(session, live.id, ("started",), state="cancelled",
                                  live_for=None, ended_at=now)
    await session.flush()

    young = now - service._aware(agent.created_at) < NEW_AGENT
    via = "setup" if young and not await crud.ever_owned(session, address) else "link"
    email_hmac = vault.lookup(email)
    token = new_token()
    expires_at = now + REQUEST_TTL
    row = OwnerRequest(
        agent_address=address, email_hmac=email_hmac, email_enc=vault.encrypt(email),
        token_hash=_token_hash(token), via=via, state="open", live_for=address,
        created_at=now, expires_at=expires_at,
    )
    if await crud.blocked_agent(session, email_hmac, address):
        # "Stop this agent asking": recorded, ended at once, never shown.
        row.state, row.live_for, row.ended_at = "declined", None, now
    else:
        row.emailed = await _may_email(session, settings, email_hmac, address, now)
    session.add(row)
    try:
        await session.flush()
    except IntegrityError:
        await session.rollback()
        raise PasskeyError(409, "busy", "This agent is already asking. Try again.") from None
    found = await owner_crud.find_by_email(session, email_hmac)
    has_account = found is not None and found[0].owner_id is not None
    if found is not None:
        await owner_crud.audit(session, found[0].id, "request_received",
                               {"request": row.id, "emailed": row.emailed})
    await session.commit()

    agent_key = links.agent_key_of(agent)
    reply = {"detail": REPLY, "words": words_for(agent_key), "via": via,
             "expiresAt": links._stamp(expires_at)}
    if row.emailed:
        origin = settings.owner_origin
        sink(email, {
            "agent": address, "words": reply["words"], "via": via,
            "expiresAt": reply["expiresAt"], "hasAccount": has_account,
            "url": f"{origin}/#request={token}", "neverUrl": f"{origin}/#never={token}",
        })
    return reply


async def _may_email(
    session: AsyncSession, settings, email_hmac: str, agent: str, now: datetime
) -> bool:
    if await crud.opted_out(session, email_hmac, agent):
        return False
    hour = await crud.emailed_since(session, now - timedelta(hours=1), email_hmac)
    if hour >= EMAILS_PER_ADDRESS_HOUR:
        return False
    if await crud.emailed_since(session, now - timedelta(days=1), email_hmac) >= EMAILS_PER_ADDRESS_DAY:
        return False
    sent_today = await crud.emailed_since(session, now - timedelta(days=1))
    return sent_today < settings.owner_request_emails_per_day


async def agent_view(session: AsyncSession, settings, agent: Agent) -> dict[str, Any] | None:
    """The agent's newest request, and the link body to sign once the owner
    accepted it (``offer``). Only a link its own request started is offered."""
    row = await crud.newest_request(session, agent.address)
    if row is None:
        return None
    now = service.utcnow()
    link = await _link(session, row)
    state = state_of(row, link, now)
    out: dict[str, Any] = {
        "request": {"state": state, "via": row.via, "expiresAt": links._stamp(row.expires_at)},
    }
    if state == "waiting_for_agent" and link is not None and link.live_for == agent.address:
        valid_from = parse_body(link.body)["validFrom"]
        if links._stamp(now - OFFER_FRESH) > valid_from:
            owner = await session.get(Owner, link.owner_pk)
            links.rebuild(settings, owner, link, now)
            await session.commit()
        out["offer"] = {"link": link.id, "body": link.body, "hash": link.hash, "via": link.via}
    return out


# --- the owner's side -----------------------------------------------------------


def _ended() -> PasskeyError:
    return PasskeyError(410, "ended", "This request has ended.")


async def open_request(
    session: AsyncSession, vault: EmailVault, token: str
) -> tuple[Owner, OwnerRequest]:
    """The request a token names, and its email's account, made now if
    there is none (the token confirms the email)."""
    row = await crud.by_token(session, _token_hash(token))
    if row is None:
        raise PasskeyError(404, "no_request", "This link doesn't work.")
    now = service.utcnow()
    if await _settle(session, row, now) in ENDED:
        await session.commit()
        raise _ended()
    await owner_crud.drop_unfinished_signups(session, now - service.SIGNUP_TTL)
    found = await owner_crud.find_by_email(session, row.email_hmac)
    if found is None:
        try:
            await owner_crud.create_owner(
                session, email_hmac=row.email_hmac, email_enc=row.email_enc,
                created_via="request",
            )
        except owner_crud.EmailTaken:
            pass  # made a moment ago by a sign-up or another open
        await session.refresh(row)
        found = await owner_crud.find_by_email(session, row.email_hmac)
    owner, owner_email = found
    if owner.status != "active":
        await session.rollback()
        raise _ended()
    if owner_email.verified_at is None:
        owner_email.verified_at = now
    row.owner_pk = owner.id
    await owner_crud.audit(session, owner.id, "request_opened", {"request": row.id})
    await session.commit()
    return owner, row


async def scoped_session(session: AsyncSession, owner: Owner, row: OwnerRequest) -> str:
    """A session that can only finish *row*: its token for the cookie."""
    now = service.utcnow()
    token = new_token()
    await owner_crud.add_session(
        session, owner_pk=owner.id, token_hash=session_token_hash(token), now=now,
        expires_at=now + service.SESSION_MAX, request_id=row.id,
    )
    await session.commit()
    return token


async def _mine(
    session: AsyncSession, owner: Owner, request_id: int, scope: int | None
) -> OwnerRequest:
    """A request to this owner's email (and, for a scoped session, its own)."""
    if scope is not None and scope != request_id:
        raise PasskeyError(403, "not_yours", "This session can only see its own request.")
    row = await session.get(OwnerRequest, request_id)
    email = await owner_crud.primary_email(session, owner.id)
    if row is None or email is None or row.email_hmac != email.email_hmac:
        raise PasskeyError(404, "no_request", "No such request.")
    return row


async def list_requests(
    session: AsyncSession, owner: Owner, scope: int | None
) -> list[dict[str, Any]]:
    """A scoped session's own request, whatever its state; otherwise the
    requests waiting on this account."""
    now = service.utcnow()
    if scope is not None:
        return [await view(session, await _mine(session, owner, scope, scope), now)]
    email = await owner_crud.primary_email(session, owner.id)
    if email is None:
        return []
    shown = []
    for row in await crud.live_for_email(session, email.email_hmac):
        item = await view(session, row, now)
        if item["state"] in WAITING:
            shown.append(item)
    return shown


async def get_request(
    session: AsyncSession, owner: Owner, request_id: int, scope: int | None
) -> dict[str, Any]:
    row = await _mine(session, owner, request_id, scope)
    now = service.utcnow()
    await _settle(session, row, now)
    await session.commit()
    return await view(session, row, now)


async def link_of(session: AsyncSession, request_id: int) -> int | None:
    row = await session.get(OwnerRequest, request_id)
    return row.link_id if row else None


async def settle_approved(session: AsyncSession, link_ids: list[int]) -> None:
    """Mark the requests whose links were just approved as approved."""
    now = service.utcnow()
    for link_id in link_ids:
        row = await crud.by_link(session, link_id)
        if row is not None and row.live_for is not None:
            row.state, row.live_for, row.ended_at = "approved", None, now
    await session.commit()


async def accept(
    session: AsyncSession, settings, owner: Owner, request_id: int, scope: int | None
) -> dict[str, Any]:
    """Build the link for the agent to sign; the owner approves it after."""
    row = await _mine(session, owner, request_id, scope)
    now = service.utcnow()
    if await _settle(session, row, now) != "open":
        await session.commit()
        raise PasskeyError(409, "not_open", "This request isn't waiting to be accepted.")
    head = await owner_crud.key_log_head(session, owner.id)
    if owner.owner_id is None or head is None:
        raise PasskeyError(409, "no_passkey", "Add a passkey first.")
    agent = await session.get(Agent, row.agent_address)
    live = await link_crud.live_link(session, row.agent_address)
    if live is not None and live.state != "started":
        raise PasskeyError(409, "has_owner", "This agent has an owner now, or is waiting for one.")
    if live is not None:
        await link_crud.move_link(session, live.id, ("started",), state="cancelled",
                                  live_for=None, ended_at=now)
    link = await links.new_link(session, settings, owner, head.hash, agent, row.via, now)
    row.state, row.link_id, row.owner_pk = "accepted", link.id, owner.id
    await owner_crud.audit(session, owner.id, "request_accepted",
                           {"request": row.id, "link": link.id})
    await session.commit()
    return await view(session, row, now)


async def decline(
    session: AsyncSession, owner: Owner, request_id: int, block: bool, scope: int | None
) -> dict[str, Any]:
    """Say no; with *block*, this agent's requests to this email stop too."""
    row = await _mine(session, owner, request_id, scope)
    now = service.utcnow()
    if await _settle(session, row, now) not in WAITING:
        await session.commit()
        raise _ended()
    await _close(session, row, "declined", now)
    if block:
        await crud.add_opt_out(session, row.email_hmac, row.agent_address, now)
    await owner_crud.audit(session, owner.id, "request_declined",
                           {"request": row.id, "block": block})
    await session.commit()
    return await view(session, row, now)


async def never(session: AsyncSession, token: str) -> None:
    """"Never email me about agents": the token proves the email."""
    row = await crud.by_token(session, _token_hash(token))
    if row is None:
        raise PasskeyError(404, "no_request", "This link doesn't work.")
    now = service.utcnow()
    await crud.add_opt_out(session, row.email_hmac, None, now)
    if await _settle(session, row, now) in WAITING:
        await _close(session, row, "declined", now)
    await session.commit()

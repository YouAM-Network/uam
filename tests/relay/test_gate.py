"""recipient_gate: who may deliver to an agent with an inbound policy (P1).

Every cell of the decision table in specs/P1.md §3.2. The gate only reads;
the tests check that too.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import func, select

from uam.db.models import Agent, InboundContact, InboundPolicy, RoutedMessage
from uam.relay.gate import recipient_gate

BOB = "bob::test.local"
ALICE = "alice::other.example"
ALICE_KEY = "alice-key"
MESSAGE = "message"
RECEIPT = "receipt.read"
KNOCK = "handshake.request"


@pytest.fixture
async def session(session_factory):
    async with session_factory() as s:
        s.add(Agent(address=BOB, public_key="pk", token_hash="h"))
        await s.commit()
        yield s


async def _policy(session, policy):
    session.add(InboundPolicy(agent_address=BOB, policy=policy, set_by="admin"))
    await session.commit()


async def _contact(session, state="allowed", key=ALICE_KEY, expires_at=None):
    session.add(InboundContact(
        agent_address=BOB, contact_address=ALICE, contact_key=key,
        state=state, source="admin", expires_at=expires_at,
    ))
    await session.commit()


async def _gate(session, *, type=MESSAGE, key=ALICE_KEY, reply_to=None):
    return await recipient_gate(
        session, recipient=BOB, sender=ALICE, message_type=type,
        sender_key=key, reply_to=reply_to,
    )


# --- no policy / open -------------------------------------------------------


@pytest.mark.parametrize("type", [MESSAGE, KNOCK, RECEIPT])
async def test_no_policy_passes_everything(session, type):
    assert await _gate(session, type=type)


async def test_open_passes_strangers(session):
    await _policy(session, "open")
    assert await _gate(session)


async def test_open_passes_even_a_blocked_row(session):
    # Rows only matter under contacts/closed; open is today's behaviour.
    await _policy(session, "open")
    await _contact(session, state="blocked")
    assert await _gate(session)


# --- contacts / closed --------------------------------------------------------


@pytest.mark.parametrize("policy", ["contacts", "closed"])
@pytest.mark.parametrize("type", [MESSAGE, KNOCK, RECEIPT])
async def test_strangers_are_pending_for_every_type(session, policy, type):
    await _policy(session, policy)
    assert not await _gate(session, type=type)


@pytest.mark.parametrize("policy", ["contacts", "closed"])
async def test_an_allowed_contact_with_its_key_passes(session, policy):
    await _policy(session, policy)
    await _contact(session)
    assert await _gate(session)


@pytest.mark.parametrize("policy", ["contacts", "closed"])
async def test_an_allowed_contact_with_another_key_is_pending(session, policy):
    await _policy(session, policy)
    await _contact(session)
    assert not await _gate(session, key="someone-elses-key")


@pytest.mark.parametrize("policy", ["contacts", "closed"])
@pytest.mark.parametrize("type", [MESSAGE, KNOCK, RECEIPT])
async def test_blocked_is_pending_for_every_type(session, policy, type):
    await _policy(session, policy)
    await _contact(session, state="blocked")
    assert not await _gate(session, type=type)


async def test_an_expired_row_counts_as_no_row(session):
    await _policy(session, "contacts")
    await _contact(session, expires_at=datetime.now(timezone.utc) - timedelta(seconds=1))
    assert not await _gate(session)


async def test_a_row_that_has_not_expired_passes(session):
    await _policy(session, "contacts")
    await _contact(session, expires_at=datetime.now(timezone.utc) + timedelta(days=1))
    assert await _gate(session)


# --- receipts ---------------------------------------------------------------


async def test_a_receipt_for_mail_bob_sent_alice_passes(session):
    await _policy(session, "contacts")
    session.add(RoutedMessage(message_id="m1", from_addr=BOB, to_addr=ALICE))
    await session.commit()
    assert await _gate(session, type=RECEIPT, reply_to="m1")


@pytest.mark.parametrize("routed", [
    ("m1", ALICE, BOB),             # the wrong direction
    ("m1", BOB, "carol::x"),        # to someone else
])
async def test_other_receipts_are_pending(session, routed):
    await _policy(session, "contacts")
    message_id, frm, to = routed
    session.add(RoutedMessage(message_id=message_id, from_addr=frm, to_addr=to))
    await session.commit()
    assert not await _gate(session, type=RECEIPT, reply_to="m1")


async def test_a_reply_to_on_a_plain_message_does_not_bind(session):
    await _policy(session, "contacts")
    session.add(RoutedMessage(message_id="m1", from_addr=BOB, to_addr=ALICE))
    await session.commit()
    assert not await _gate(session, type=MESSAGE, reply_to="m1")


# --- reads only ---------------------------------------------------------------


async def test_the_gate_writes_nothing(session):
    await _policy(session, "contacts")
    session.add(RoutedMessage(message_id="m1", from_addr=BOB, to_addr=ALICE))
    await session.commit()

    await _gate(session, type=RECEIPT, reply_to="m1")

    assert not session.new and not session.dirty
    count = (await session.execute(
        select(RoutedMessage.receipt_count).where(RoutedMessage.message_id == "m1")
    )).scalar_one()
    assert count == 0
    assert (await session.execute(select(func.count()).select_from(InboundContact))).scalar_one() == 0

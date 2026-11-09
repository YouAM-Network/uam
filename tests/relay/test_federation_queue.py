"""The federation retry queue: one bad row can't hold up the rest."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock

import pytest

from uam.db.crud.federation import enqueue_federation, get_pending_queue
from uam.db.engine import get_engine
from uam.db.models import FederationQueueEntry
from uam.db.session import init_session_factory
from uam.relay.federation import ForwardResult, retry_pending_federation
from uam.relay.ssrf import SSRFBlockedError, is_public_ip, resolve_pinned
from sqlmodel import select

# Valid to parse_address, but getaddrinfo raises UnicodeError on a 64-byte label.
UNRESOLVABLE = "a" * 64 + ".example"


def test_a_name_dns_can_t_encode_is_a_refusal_not_a_crash():
    assert is_public_ip(UNRESOLVABLE) is False
    with pytest.raises(SSRFBlockedError):
        resolve_pinned(UNRESOLVABLE)


def _queue(client, *domains):
    async def run():
        factory = await init_session_factory(get_engine())
        async with factory() as session:
            for domain in domains:
                await enqueue_federation(session, domain, json.dumps({"to": f"x::{domain}"}))

    client.portal.call(run)


def _rows(client):
    async def run():
        factory = await init_session_factory(get_engine())
        async with factory() as session:
            found = await session.execute(
                select(FederationQueueEntry).order_by(FederationQueueEntry.id)
            )
            return [(row.status, row.attempt_count) for row in found.scalars().all()]

    return client.portal.call(run)


def _retry(client, app, service):
    async def run():
        factory = await init_session_factory(get_engine())
        await retry_pending_federation(factory, service, app.state.settings)

    client.portal.call(run)


def test_a_row_that_raises_counts_as_an_attempt_and_the_next_row_still_goes(client, app):
    _queue(client, "bad.example", "good.example")
    service = AsyncMock()
    service.forward.side_effect = [
        RuntimeError("boom"),
        ForwardResult(delivered=True),
    ]

    _retry(client, app, service)

    assert service.forward.await_count == 2
    assert _rows(client) == [("pending", 1), ("delivered", 1)]


def test_a_failed_row_goes_to_the_back_of_the_retry_schedule(client, app):
    _queue(client, "bad.example")
    service = AsyncMock()
    service.forward.side_effect = RuntimeError("boom")

    _retry(client, app, service)

    async def due():
        factory = await init_session_factory(get_engine())
        async with factory() as session:
            return await get_pending_queue(session)

    assert client.portal.call(due) == []


def test_a_forward_that_raises_leaves_the_send_queued(client, app, registered_agent, make_envelope):
    from uam.relay.federation import forward_to_peer

    app.state.federation_service = AsyncMock()
    app.state.federation_service.forward.side_effect = RuntimeError("boom")

    async def run():
        factory = await init_session_factory(get_engine())
        async with factory() as session:
            return await forward_to_peer(app.state, session, "x::peer.example", {"to": "x::peer.example"})

    assert client.portal.call(run) == "queued"
    assert _rows(client) == [("pending", 0)]

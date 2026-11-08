"""A webhook that fails doesn't lose the message, or claim it arrived."""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from uam.db.crud.agents import set_webhook
from uam.db.crud.webhooks import record_attempt, create_delivery, get_deliveries_for_agent
from uam.db.engine import get_engine
from uam.db.session import init_session_factory
from uam.relay.rate_limit import SlidingWindowCounter
from uam.relay.webhook import WebhookCircuitBreaker


def _auth(agent):
    return {"Authorization": f"Bearer {agent['token']}"}


def _send(client, sender, wire):
    return client.post("/api/v1/send", json={"envelope": wire}, headers=_auth(sender))


def _inbox_ids(client, agent):
    resp = client.get(f"/api/v1/inbox/{agent['address']}", headers=_auth(agent))
    return [m["message_id"] for m in resp.json()["messages"]]


def _in_session(client, work):
    async def run():
        factory = await init_session_factory(get_engine())
        async with factory() as session:
            return await work(session)

    return client.portal.call(run)


def _wait_for_deliveries(client, app):
    async def run():
        tasks = list(app.state.webhook_service._active_tasks)
        if tasks:
            await asyncio.gather(*tasks)

    client.portal.call(run)


@pytest.fixture()
def bob_webhook(client, app, registered_agent_pair):
    """bob has a webhook; the test sets what it answers."""
    _, bob = registered_agent_pair
    _in_session(
        client, lambda session: set_webhook(session, bob["address"], "https://hook.example/x")
    )
    post = AsyncMock(return_value=httpx.Response(500))
    app.state.webhook_service._http_client = AsyncMock(post=post, aclose=AsyncMock())
    with (
        patch("uam.relay.webhook.RETRY_DELAYS", [0, 0]),
        patch(
            "uam.relay.webhook.async_validate_webhook_url",
            AsyncMock(return_value=(True, "")),
        ) as validate,
    ):
        yield post, validate


@pytest.mark.parametrize("status", [500, 410])
def test_a_failed_webhook_leaves_the_message_in_the_inbox(
    client, app, registered_agent_pair, make_envelope, bob_webhook, status
):
    alice, bob = registered_agent_pair
    post, _ = bob_webhook
    post.return_value = httpx.Response(status)
    wire = make_envelope(alice, bob)

    assert _send(client, alice, wire).status_code == 200
    _wait_for_deliveries(client, app)

    assert _inbox_ids(client, bob) == [wire["message_id"]]


def test_a_webhook_url_gone_bad_leaves_the_message_in_the_inbox(
    client, app, registered_agent_pair, make_envelope, bob_webhook
):
    alice, bob = registered_agent_pair
    _, validate = bob_webhook
    validate.return_value = (False, "private address")
    wire = make_envelope(alice, bob)

    assert _send(client, alice, wire).status_code == 200
    _wait_for_deliveries(client, app)

    assert _inbox_ids(client, bob) == [wire["message_id"]]


def test_a_delivered_receipt_waits_for_the_webhook_to_succeed(
    client, app, registered_agent_pair, make_envelope, bob_webhook
):
    alice, bob = registered_agent_pair
    sent = []
    real_send_to = app.state.manager.send_to

    async def spy(address, data):
        sent.append(data)
        return await real_send_to(address, data)

    app.state.manager.send_to = spy

    assert _send(client, alice, make_envelope(alice, bob)).status_code == 200
    _wait_for_deliveries(client, app)

    assert [m for m in sent if m.get("type") == "receipt.delivered"] == []


def test_a_successful_webhook_sends_one_receipt(
    client, app, registered_agent_pair, make_envelope, bob_webhook
):
    alice, bob = registered_agent_pair
    post, _ = bob_webhook
    post.return_value = httpx.Response(200)
    sent = []
    real_send_to = app.state.manager.send_to

    async def spy(address, data):
        sent.append(data)
        return await real_send_to(address, data)

    app.state.manager.send_to = spy
    wire = make_envelope(alice, bob)

    assert _send(client, alice, wire).status_code == 200
    _wait_for_deliveries(client, app)

    receipts = [m for m in sent if m.get("type") == "receipt.delivered"]
    assert [m["message_id"] for m in receipts] == [wire["message_id"]]
    assert _inbox_ids(client, bob) == []


def test_a_delivery_row_names_its_message(
    client, app, registered_agent_pair, make_envelope, bob_webhook
):
    alice, bob = registered_agent_pair
    wire = make_envelope(alice, bob)

    _send(client, alice, wire)
    _wait_for_deliveries(client, app)

    rows = _in_session(
        client, lambda session: get_deliveries_for_agent(session, bob["address"])
    )
    assert [row.message_id for row in rows] == [wire["message_id"]]


def test_a_delivery_a_restart_interrupted_reaches_the_inbox(
    client, app, registered_agent_pair, make_envelope
):
    alice, bob = registered_agent_pair
    wire = make_envelope(alice, bob)

    _in_session(
        client,
        lambda session: create_delivery(
            session, bob["address"], wire["message_id"], json.dumps(wire)
        ),
    )

    client.portal.call(app.state.webhook_service.recover_interrupted)

    assert _inbox_ids(client, bob) == [wire["message_id"]]
    rows = _in_session(
        client, lambda session: get_deliveries_for_agent(session, bob["address"])
    )
    assert [row.status for row in rows] == ["failed"]


def test_a_delivery_waiting_between_retries_also_reaches_the_inbox(
    client, app, registered_agent_pair, make_envelope
):
    """One failed attempt makes a row in_progress; it waits hours for the next."""
    alice, bob = registered_agent_pair
    wire = make_envelope(alice, bob)

    async def waiting(session):
        delivery = await create_delivery(
            session, bob["address"], wire["message_id"], json.dumps(wire)
        )
        await record_attempt(session, delivery.id, status_code=503)

    _in_session(client, waiting)

    client.portal.call(app.state.webhook_service.recover_interrupted)

    assert _inbox_ids(client, bob) == [wire["message_id"]]


def test_a_failed_probe_opens_the_circuit_again():
    breaker = WebhookCircuitBreaker()
    for _ in range(breaker.FAILURE_THRESHOLD):
        breaker.record_failure("bob::test.local")
    breaker._circuits["bob::test.local"].opened_at -= breaker._cooldown_seconds + 1
    assert breaker.is_available("bob::test.local")  # cooled down: a probe may go

    breaker.record_failure("bob::test.local")

    assert not breaker.is_available("bob::test.local")


# -- POST /messages/{id}/receipt ----------------------------------------------


def test_the_receipt_route_uses_the_receipt_bucket(
    client, app, registered_agent_pair, make_envelope
):
    alice, bob = registered_agent_pair
    wire = make_envelope(alice, bob)
    _send(client, alice, wire)
    app.state.receipt_limiter = SlidingWindowCounter(limit=1, window_seconds=60.0)
    forwarded = AsyncMock(return_value=True)
    app.state.manager.send_to = forwarded
    url = f"/api/v1/messages/{wire['message_id']}/receipt"

    for _ in range(3):
        resp = client.post(url, json={"type": "receipt.read"}, headers=_auth(bob))
        assert resp.status_code == 200

    assert forwarded.await_count == 1


def test_the_receipt_route_takes_only_real_receipts(
    client, registered_agent_pair, make_envelope
):
    alice, bob = registered_agent_pair
    wire = make_envelope(alice, bob)
    _send(client, alice, wire)

    resp = client.post(
        f"/api/v1/messages/{wire['message_id']}/receipt",
        json={"type": "receipt.anything"},
        headers=_auth(bob),
    )

    assert resp.status_code == 422

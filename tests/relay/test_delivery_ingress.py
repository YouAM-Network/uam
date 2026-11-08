"""What REST and the WebSocket do with messages they shouldn't simply take."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest
from starlette.websockets import WebSocketDisconnect

from uam.db.crud.agents import deactivate_agent, suspend_agent
from uam.db.engine import get_engine
from uam.db.session import init_session_factory
from uam.protocol import (
    MessageType,
    create_envelope,
    generate_keypair,
    serialize_verify_key,
    to_wire_dict,
)
from uam.relay.policy import parse_expires
from uam.relay.rate_limit import SlidingWindowCounter


def _auth(agent):
    return {"Authorization": f"Bearer {agent['token']}"}


def _send(client, sender, wire):
    return client.post("/api/v1/send", json={"envelope": wire}, headers=_auth(sender))


def _wire(sender, to_address, verify_key, message_type=MessageType.MESSAGE, **kwargs):
    return to_wire_dict(
        create_envelope(
            from_address=sender["address"],
            to_address=to_address,
            message_type=message_type,
            payload_plaintext=b"hello",
            signing_key=sender["signing_key"],
            recipient_verify_key=verify_key,
            **kwargs,
        )
    )


def _ws_exchange(client, sender, frame):
    with client.websocket_connect("/ws", headers=_auth(sender)) as ws:
        ws.send_json(frame)
        return ws.receive_json()


def _set_status(client, change, address):
    async def run():
        factory = await init_session_factory(get_engine())
        async with factory() as session:
            await change(session, address)

    client.portal.call(run)


# -- duplicates ---------------------------------------------------------------


def test_rest_duplicates_count_against_the_sender(
    client, app, registered_agent_pair, make_envelope
):
    alice, bob = registered_agent_pair
    app.state.sender_limiter = SlidingWindowCounter(limit=3, window_seconds=60.0)
    app.state.reputation_manager.get_send_limit = lambda _sender: 3
    wire = make_envelope(alice, bob)

    statuses = [_send(client, alice, wire).status_code for _ in range(5)]

    assert statuses == [200, 200, 200, 429, 429]


def test_ws_duplicates_count_against_the_sender(
    client, app, registered_agent_pair, make_envelope
):
    alice, bob = registered_agent_pair
    app.state.sender_limiter = SlidingWindowCounter(limit=2, window_seconds=60.0)
    app.state.reputation_manager.get_send_limit = lambda _sender: 2
    wire = make_envelope(alice, bob)

    with client.websocket_connect("/ws", headers=_auth(alice)) as ws:
        replies = []
        for _ in range(4):
            ws.send_json(wire)
            reply = ws.receive_json()
            while reply.get("type") == "receipt.delivered":
                reply = ws.receive_json()
            replies.append(reply.get("error") or reply["type"])

    assert replies == ["ack", "ack", "rate_limited", "rate_limited"]


# -- recipients ---------------------------------------------------------------


def test_rest_mail_for_nobody_here_is_refused(client, registered_agent_pair, make_envelope):
    alice, bob = registered_agent_pair
    wire = make_envelope(alice, {**bob, "address": "nobody::test.local"})

    assert _send(client, alice, wire).status_code == 404


def test_ws_mail_for_nobody_here_leaves_the_connection_open(
    client, registered_agent_pair, make_envelope
):
    alice, bob = registered_agent_pair
    with client.websocket_connect("/ws", headers=_auth(alice)) as ws:
        ws.send_json(make_envelope(alice, {**bob, "address": "nobody::test.local"}))
        assert ws.receive_json()["error"] == "unknown_recipient"

        ws.send_json(make_envelope(alice, bob))
        assert ws.receive_json()["type"] == "ack"


def test_mail_for_another_relay_is_refused_when_federation_is_off(
    client, app, registered_agent_pair, make_envelope, monkeypatch
):
    alice, bob = registered_agent_pair
    monkeypatch.setattr(app.state.settings, "federation_enabled", False)
    wire = make_envelope(alice, {**bob, "address": "carol::elsewhere.example"})

    assert _send(client, alice, wire).status_code == 404


@pytest.mark.parametrize(
    ("result", "delivered"), [("delivered", True), ("queued", False)]
)
def test_ws_mail_for_another_relay_is_forwarded(
    client, app, registered_agent_pair, make_envelope, monkeypatch, result, delivered
):
    alice, bob = registered_agent_pair
    forward = AsyncMock(
        return_value=AsyncMock(delivered=result == "delivered", queued=result == "queued")
    )
    app.state.federation_service = AsyncMock(forward=forward)
    monkeypatch.setattr(app.state.settings, "federation_enabled", True)
    wire = make_envelope(alice, {**bob, "address": "carol::elsewhere.example"})

    reply = _ws_exchange(client, alice, wire)

    assert reply == {"type": "ack", "message_id": wire["message_id"], "delivered": delivered}
    forward.assert_awaited_once()


def test_forwarded_mail_is_queued_before_the_forward_starts(
    client, app, registered_agent_pair, make_envelope, monkeypatch
):
    """A crash mid-forward must not lose the message, and the forward runs
    outside the sender's transaction: it takes up to 30 s and writes its own log.
    """
    from sqlalchemy import text

    alice, bob = registered_agent_pair
    seen = []

    async def forward(**_kwargs):
        factory = await init_session_factory(get_engine())
        async with factory() as session:
            rows = await session.execute(text("select status from federation_queue"))
            seen.extend(rows.scalars().all())
        return AsyncMock(delivered=True, queued=False)

    app.state.federation_service = AsyncMock(forward=forward)
    monkeypatch.setattr(app.state.settings, "federation_enabled", True)

    resp = _send(client, alice, make_envelope(alice, {**bob, "address": "carol::elsewhere.example"}))

    assert resp.status_code == 200
    assert seen == ["pending"]

    async def statuses():
        factory = await init_session_factory(get_engine())
        async with factory() as session:
            rows = await session.execute(text("select status from federation_queue"))
            return list(rows.scalars().all())

    assert client.portal.call(statuses) == ["delivered"]


# -- reconnecting -------------------------------------------------------------


def test_live_mail_reaches_an_agent_that_reconnected(
    client, registered_agent_pair, make_envelope
):
    alice, bob = registered_agent_pair
    with client.websocket_connect("/ws", headers=_auth(bob)) as first:
        with client.websocket_connect("/ws", headers=_auth(bob)) as second:
            with pytest.raises(WebSocketDisconnect):
                first.receive_json()  # the old socket's cleanup has run

            wire = make_envelope(alice, bob)
            assert _send(client, alice, wire).json()["delivered"] is True

            assert second.receive_json()["message_id"] == wire["message_id"]


# -- size and shape -----------------------------------------------------------


def test_ws_refuses_an_oversized_envelope(client, registered_agent_pair, make_envelope):
    alice, bob = registered_agent_pair
    wire = make_envelope(alice, bob)
    wire["payload"] = "A" * 70_000

    assert _ws_exchange(client, alice, wire)["error"] == "envelope_too_large"


@pytest.mark.parametrize("frame", [[1, 2], "uam_version", 7, None])
def test_ws_refuses_a_frame_that_is_not_an_object(client, registered_agent_pair, frame):
    alice, _ = registered_agent_pair

    assert _ws_exchange(client, alice, frame)["error"] == "unknown_message_type"


def test_ws_survives_a_frame_that_is_not_json(client, registered_agent_pair, make_envelope):
    alice, bob = registered_agent_pair
    with client.websocket_connect("/ws", headers=_auth(alice)) as ws:
        ws.send_text("not json")
        assert ws.receive_json()["error"] == "invalid_json"
        ws.send_bytes(b"\x00\x01")
        assert ws.receive_json()["error"] == "invalid_json"

        ws.send_json(make_envelope(alice, bob))
        assert ws.receive_json()["type"] == "ack"


def test_a_replaced_connection_is_not_logged_as_an_error(
    client, registered_agent_pair, caplog
):
    _, bob = registered_agent_pair
    with client.websocket_connect("/ws", headers=_auth(bob)) as first:
        with client.websocket_connect("/ws", headers=_auth(bob)):
            with pytest.raises(WebSocketDisconnect):
                first.receive_json()

    assert "WebSocket error" not in caplog.text


def test_ws_refuses_a_bad_signature(client, registered_agent_pair, make_envelope):
    alice, bob = registered_agent_pair
    wire = make_envelope(alice, bob)
    wire["signature"] = make_envelope(alice, bob)["signature"]

    assert _ws_exchange(client, alice, wire)["error"] == "invalid_signature"


# -- receipts -----------------------------------------------------------------


def test_only_real_receipt_types_skip_the_sender_limit(
    client, app, registered_agent_pair, make_envelope
):
    alice, bob = registered_agent_pair
    app.state.reputation_manager.get_send_limit = lambda _sender: 0
    wire = make_envelope(alice, bob)
    wire["type"] = "receipt.anything"

    assert _send(client, alice, wire).status_code == 403


def test_a_receipt_past_its_bucket_writes_nothing(
    client, app, registered_agent_pair, make_envelope
):
    alice, bob = registered_agent_pair
    app.state.receipt_limiter = SlidingWindowCounter(limit=0, window_seconds=60.0)
    wire = _wire(
        alice,
        bob["address"],
        bob["verify_key"],
        MessageType.RECEIPT_READ,
    )

    resp = _send(client, alice, wire)
    assert resp.status_code == 200
    assert resp.json()["delivered"] is False

    async def seen():
        from sqlalchemy import text

        factory = await init_session_factory(get_engine())
        async with factory() as session:
            rows = await session.execute(text("select count(*) from seen_message_ids"))
            return rows.scalar_one()

    assert client.portal.call(seen) == 0


def test_a_third_party_cannot_bind_a_receipt(
    client, app, registered_agent_pair, make_envelope
):
    """Only the recipient of a message can send its bound receipts."""
    alice, bob = registered_agent_pair
    sk, vk = generate_keypair()
    resp = client.post(
        "/api/v1/register",
        json={"agent_name": "mallory", "public_key": serialize_verify_key(vk)},
    )
    mallory = {**resp.json(), "signing_key": sk, "verify_key": vk}
    original = make_envelope(alice, bob)
    assert _send(client, alice, original).status_code == 200
    app.state.receipt_limiter = SlidingWindowCounter(limit=0, window_seconds=60.0)

    forged = _wire(
        mallory,
        alice["address"],
        alice["verify_key"],
        MessageType.RECEIPT_READ,
        reply_to=original["message_id"],
    )
    genuine = _wire(
        bob,
        alice["address"],
        alice["verify_key"],
        MessageType.RECEIPT_READ,
        reply_to=original["message_id"],
    )

    assert _send(client, mallory, forged).json()["delivered"] is False
    assert _send(client, bob, genuine).status_code == 200
    assert client.get(
        f"/api/v1/inbox/{alice['address']}", headers=_auth(alice)
    ).json()["messages"][0]["message_id"] == genuine["message_id"]


# -- agents that are not active -----------------------------------------------


@pytest.mark.parametrize("change", [suspend_agent, deactivate_agent])
def test_an_agent_that_is_not_active_cannot_send(
    client, registered_agent_pair, make_envelope, change
):
    alice, bob = registered_agent_pair
    _set_status(client, change, alice["address"])

    assert _send(client, alice, make_envelope(alice, bob)).status_code == 401


@pytest.mark.parametrize("change", [suspend_agent, deactivate_agent])
def test_an_agent_that_is_not_active_cannot_connect(
    client, registered_agent_pair, change
):
    alice, _ = registered_agent_pair
    _set_status(client, change, alice["address"])

    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/ws", headers=_auth(alice)):
            pass


def test_a_connected_agent_that_is_suspended_stops_sending(
    client, registered_agent_pair, make_envelope
):
    alice, bob = registered_agent_pair
    with client.websocket_connect("/ws", headers=_auth(alice)) as ws:
        _set_status(client, suspend_agent, alice["address"])
        ws.send_json(make_envelope(alice, bob))

        assert ws.receive_json()["error"] == "sender_not_active"


# -- spelling -----------------------------------------------------------------


def test_the_blocklist_ignores_case(app, client):
    spam_filter = app.state.spam_filter
    spam_filter._blocked_exact.add("spammer::evil.example")
    spam_filter._blocked_domains.add("bad.example")

    assert spam_filter.is_blocked("SPAMMER::Evil.Example")
    assert spam_filter.is_blocked("anyone::BAD.example")


# -- stored mail --------------------------------------------------------------


def test_reconnecting_drains_more_than_one_batch(
    client, registered_agent_pair, make_envelope
):
    alice, bob = registered_agent_pair
    client.app.state.sender_limiter = SlidingWindowCounter(limit=1000, window_seconds=60.0)
    client.app.state.reputation_manager.get_send_limit = lambda _sender: 1000
    sent = {}
    for _ in range(60):
        wire = make_envelope(alice, bob)
        sent[wire["message_id"]] = wire
        assert _send(client, alice, wire).status_code == 200

    with client.websocket_connect("/ws", headers=_auth(bob)) as ws:
        got = {ws.receive_json()["message_id"] for _ in range(60)}

    assert got == set(sent)
    assert json.dumps(sorted(got)) == json.dumps(sorted(sent))


# -- coming back --------------------------------------------------------------


def test_a_deactivated_agent_can_reactivate(client, registered_agent_pair, make_envelope):
    alice, bob = registered_agent_pair
    _set_status(client, deactivate_agent, alice["address"])

    resp = client.post(f"/api/v1/agents/{alice['address']}/reactivate", headers=_auth(alice))

    assert resp.status_code == 200, resp.text
    assert _send(client, alice, make_envelope(alice, bob)).status_code == 200


def test_a_suspended_agent_cannot_reactivate_itself(client, registered_agent_pair):
    alice, _ = registered_agent_pair
    _set_status(client, suspend_agent, alice["address"])

    resp = client.post(f"/api/v1/agents/{alice['address']}/reactivate", headers=_auth(alice))

    assert resp.status_code == 401


def test_an_expiry_without_a_time_zone_is_read_as_utc():
    assert parse_expires("2030-01-01T00:00:00") == datetime(2030, 1, 1, tzinfo=timezone.utc)

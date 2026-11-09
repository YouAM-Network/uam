"""A2a: every accepted send answers with what happened to the message.

POST /send and the WebSocket ack carry ``status`` (relay/receipts.py
SEND_STATUSES) beside the old ``delivered`` bool, and the sender gets a
receipt.delivered only when the status is "delivered", never for a
handshake.  Duplicates, dropped receipts and the webhook path have their own
tests (test_dedup, test_receipts, test_webhook_one_transaction); WebSocket
federation is in test_delivery_ingress.
"""

from __future__ import annotations

import time
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest

from uam.protocol import MessageType, create_envelope, to_wire_dict
from uam.relay.federation import ForwardResult, peer_send_status
from uam.relay.receipts import (
    SEND_STATUS_FEATURE,
    delivery_receipt,
    wants_delivery_receipt,
)


def _auth(agent):
    return {"Authorization": f"Bearer {agent['token']}"}


def _wire(sender, recipient, message_type=MessageType.MESSAGE, to_address=None):
    return to_wire_dict(
        create_envelope(
            from_address=sender["address"],
            to_address=to_address or recipient["address"],
            message_type=message_type,
            payload_plaintext=b"hello",
            signing_key=sender["signing_key"],
            recipient_verify_key=recipient["verify_key"],
        )
    )


def _send(client, sender, wire):
    resp = client.post("/api/v1/send", json={"envelope": wire}, headers=_auth(sender))
    assert resp.status_code == 200, resp.text
    return resp.json()


@pytest.fixture()
def frames(app, monkeypatch):
    """Every frame the relay pushes, as (address, frame); *online* addresses take them."""
    pushed: list[tuple[str, dict]] = []
    online: set[str] = set()

    async def send_to(address, frame):
        pushed.append((address, frame))
        return address in online

    monkeypatch.setattr(app.state.manager, "send_to", send_to)
    return SimpleNamespace(pushed=pushed, online=online)


def _receipts(frames, address):
    return [f for a, f in frames.pushed if a == address and f.get("type") == "receipt.delivered"]


# -- POST /send ---------------------------------------------------------------


def test_mail_pushed_to_an_open_connection_is_delivered(
    client, registered_agent_pair, frames
):
    alice, bob = registered_agent_pair
    frames.online.add(bob["address"])
    wire = _wire(alice, bob)

    answer = _send(client, alice, wire)

    assert answer == {"message_id": wire["message_id"], "status": "delivered", "delivered": True}
    [receipt] = _receipts(frames, alice["address"])
    assert receipt["message_id"] == wire["message_id"]
    assert receipt["to"] == bob["address"]


def test_mail_for_an_offline_agent_is_stored_without_a_receipt(
    client, registered_agent_pair, frames
):
    alice, bob = registered_agent_pair
    frames.online.add(alice["address"])
    wire = _wire(alice, bob)

    answer = _send(client, alice, wire)

    assert answer == {"message_id": wire["message_id"], "status": "stored", "delivered": False}
    assert _receipts(frames, alice["address"]) == []


@pytest.mark.parametrize(
    "message_type", [MessageType.HANDSHAKE_REQUEST, MessageType.HANDSHAKE_ACCEPT]
)
def test_a_pushed_handshake_gets_no_receipt(
    client, registered_agent_pair, frames, message_type
):
    alice, bob = registered_agent_pair
    frames.online.update({alice["address"], bob["address"]})

    answer = _send(client, alice, _wire(alice, bob, message_type))

    assert answer["status"] == "delivered"
    assert _receipts(frames, alice["address"]) == []


@pytest.mark.parametrize(
    ("forwarded", "status"),
    [
        (ForwardResult(delivered=True, status="delivered"), "delivered"),
        (ForwardResult(delivered=True, status="stored"), "stored"),
        (ForwardResult(delivered=True), "relayed"),  # a peer before 1.1
        (ForwardResult(delivered=False, queued=True, error="down"), "queued"),
    ],
)
def test_mail_for_another_relay_reports_the_peers_answer(
    client, app, registered_agent_pair, frames, monkeypatch, forwarded, status
):
    alice, bob = registered_agent_pair
    frames.online.add(alice["address"])
    app.state.federation_service = AsyncMock(forward=AsyncMock(return_value=forwarded))
    monkeypatch.setattr(app.state.settings, "federation_enabled", True)

    answer = _send(client, alice, _wire(alice, bob, to_address="carol::elsewhere.example"))

    assert answer["status"] == status
    assert answer["delivered"] is (status == "delivered")
    assert len(_receipts(frames, alice["address"])) == (status == "delivered")


def test_versions_lists_send_status(client):
    assert SEND_STATUS_FEATURE in client.get("/api/v1/versions").json()["features"]


# -- WebSocket ----------------------------------------------------------------


def test_ws_ack_carries_the_status(client, registered_agent_pair):
    alice, bob = registered_agent_pair
    wire = _wire(alice, bob)

    with client.websocket_connect("/ws", headers=_auth(alice)) as ws:
        ws.send_json(wire)
        ack = ws.receive_json()

    assert ack == {
        "type": "ack",
        "message_id": wire["message_id"],
        "status": "stored",
        "delivered": False,
    }


def test_ws_push_is_delivered_with_a_receipt(client, registered_agent_pair):
    alice, bob = registered_agent_pair
    wire = _wire(alice, bob)

    with client.websocket_connect("/ws", headers=_auth(bob)) as bob_ws:
        with client.websocket_connect("/ws", headers=_auth(alice)) as ws:
            ws.send_json(wire)
            first, second = ws.receive_json(), ws.receive_json()
        assert bob_ws.receive_json()["message_id"] == wire["message_id"]

    by_type = {first["type"]: first, second["type"]: second}
    assert by_type["ack"]["status"] == "delivered"
    assert by_type["ack"]["delivered"] is True
    assert by_type["receipt.delivered"]["message_id"] == wire["message_id"]


def test_ws_error_names_the_message(client, registered_agent_pair):
    alice, bob = registered_agent_pair
    wire = _wire(alice, bob)
    wire["signature"] = _wire(alice, bob)["signature"]

    with client.websocket_connect("/ws", headers=_auth(alice)) as ws:
        ws.send_json(wire)
        error = ws.receive_json()

    assert error["error"] == "invalid_signature"
    assert error["message_id"] == wire["message_id"]


# -- picking up stored mail ---------------------------------------------------


def test_fetching_a_stored_handshake_sends_no_receipt(
    client, registered_agent_pair, frames
):
    alice, bob = registered_agent_pair
    frames.online.add(alice["address"])
    _send(client, alice, _wire(alice, bob, MessageType.HANDSHAKE_REQUEST))
    message = _wire(alice, bob)
    _send(client, alice, message)

    resp = client.get(f"/api/v1/inbox/{bob['address']}", headers=_auth(bob))

    assert resp.json()["count"] == 2
    assert [r["message_id"] for r in _receipts(frames, alice["address"])] == [
        message["message_id"]
    ]


def test_draining_a_stored_handshake_sends_no_receipt(
    client, registered_agent_pair, frames
):
    alice, bob = registered_agent_pair
    _send(client, alice, _wire(alice, bob, MessageType.HANDSHAKE_REQUEST))
    message = _wire(alice, bob)
    _send(client, alice, message)
    frames.online.update({alice["address"], bob["address"]})

    with client.websocket_connect("/ws", headers=_auth(bob)):
        deadline = time.monotonic() + 3
        while not _receipts(frames, alice["address"]) and time.monotonic() < deadline:
            time.sleep(0.02)
        time.sleep(0.1)  # a stray handshake receipt would land by now

    drained = [f["message_id"] for a, f in frames.pushed if a == bob["address"]]
    assert message["message_id"] in drained
    assert [r["message_id"] for r in _receipts(frames, alice["address"])] == [
        message["message_id"]
    ]


# -- helpers ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("message_type", "wanted"),
    [
        ("message", True),
        ("session.request", True),
        ("handshake.request", False),
        ("handshake.accept", False),
        ("handshake.anything", False),
        ("receipt.delivered", False),
        ("receipt.read", False),
    ],
)
def test_which_types_earn_a_receipt(message_type, wanted):
    assert wants_delivery_receipt(message_type) is wanted


def test_receipt_frame():
    receipt = delivery_receipt("m1", "bob::test.local")
    assert receipt["type"] == "receipt.delivered"
    assert receipt["message_id"] == "m1"
    assert receipt["to"] == "bob::test.local"
    assert receipt["timestamp"].endswith("Z")


def _peer(body, status_code=200):
    request = httpx.Request("POST", "https://peer.example/api/v1/federation/deliver")
    if isinstance(body, str):
        return httpx.Response(status_code, text=body, request=request)
    return httpx.Response(status_code, json=body, request=request)


@pytest.mark.parametrize(
    ("body", "status"),
    [
        ({"status": "delivered", "status_version": 1}, "delivered"),
        ({"status": "stored", "status_version": 1}, "stored"),
        ({"status": "duplicate", "status_version": 1}, "stored"),
        ({"status": "relayed", "status_version": 1}, "relayed"),
        ({"status": "delivered"}, "relayed"),  # 1.0.x said delivered for stored mail
        ({"status": "accepted"}, "relayed"),
        ("not json", "relayed"),
        (["delivered"], "relayed"),
    ],
)
def test_peer_status_is_trusted_only_with_a_status_version(body, status):
    assert peer_send_status(_peer(body)) == status

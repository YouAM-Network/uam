"""The delivery gate on the send paths (P1).

A message to a gated agent from anyone it hasn't approved is answered
``pending`` and leaves nothing behind: no dedup, routed or stored row, no
rate-limit slot of the recipient's. The answer is the same whatever the
reason, and the same message can be sent again once the sender is allowed.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlmodel import SQLModel

import uam.db.models  # noqa: F401
from uam.db.crud.inbound import put_contact, set_policy
from uam.db.engine import get_engine
from uam.db.session import init_session_factory
from uam.protocol import MessageType, create_envelope, to_wire_dict
from uam.protocol.crypto import generate_keypair, serialize_verify_key


def _auth(agent) -> dict:
    return {"Authorization": f"Bearer {agent['token']}"}


def _register(client, name):
    sk, vk = generate_keypair()
    resp = client.post("/api/v1/register", json={
        "agent_name": name, "public_key": serialize_verify_key(vk),
    })
    assert resp.status_code == 200, resp.text
    return {**resp.json(), "signing_key": sk, "verify_key": vk,
            "public_key": serialize_verify_key(vk)}


def _wire(frm, to, type=MessageType.MESSAGE, **kw):
    return to_wire_dict(create_envelope(
        from_address=frm["address"], to_address=to["address"], message_type=type,
        payload_plaintext=b"hi", signing_key=frm["signing_key"],
        recipient_verify_key=to["verify_key"], **kw,
    ))


def _send(client, frm, wire):
    return client.post("/api/v1/send", json={"envelope": wire}, headers=_auth(frm))


async def _db(fn, *args, **kw):
    factory = await init_session_factory(get_engine())
    async with factory() as session:
        return await fn(session, *args, **kw)


async def _counts(session):
    out = {}
    for name, table in SQLModel.metadata.tables.items():
        out[name] = (await session.execute(select(func.count()).select_from(table))).scalar_one()
    return out


@pytest.fixture()
def gated(client):
    """bob takes mail only from approved contacts; alice and carol are strangers."""
    bob = _register(client, "bob")
    alice = _register(client, "alice")
    carol = _register(client, "carol")
    client.portal.call(lambda: _db(set_policy, bob["address"], "contacts",
                                   expected_revision=0, set_by="admin"))
    return client, bob, alice, carol


def _allow(client, bob, who, state="allowed", key=None):
    client.portal.call(lambda: _db(
        put_contact, bob["address"], who["address"],
        key=key or who["public_key"], state=state, source="admin",
    ))


def test_a_stranger_gets_pending_and_nothing_is_kept(gated):
    client, bob, alice, _ = gated
    before = client.portal.call(lambda: _db(_counts))

    resp = _send(client, alice, _wire(alice, bob))

    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "pending"
    assert resp.json()["delivered"] is False
    after = client.portal.call(lambda: _db(_counts))
    assert after == before
    inbox = client.get(f"/api/v1/inbox/{bob['address']}", headers=_auth(bob)).json()
    assert inbox["count"] == 0


def test_the_same_message_goes_through_once_the_sender_is_allowed(gated):
    client, bob, alice, _ = gated
    wire = _wire(alice, bob)
    assert _send(client, alice, wire).json()["status"] == "pending"

    _allow(client, bob, alice)
    resp = _send(client, alice, wire)

    assert resp.json()["status"] == "stored"
    inbox = client.get(f"/api/v1/inbox/{bob['address']}", headers=_auth(bob)).json()
    assert [m["message_id"] for m in inbox["messages"]] == [wire["message_id"]]


def test_an_allowed_contact_is_delivered_as_before(gated):
    client, bob, alice, _ = gated
    _allow(client, bob, alice)
    assert _send(client, alice, _wire(alice, bob)).json()["status"] == "stored"


@pytest.mark.parametrize("type", [MessageType.HANDSHAKE_REQUEST, MessageType.RECEIPT_READ])
def test_handshakes_and_unbound_receipts_from_strangers_are_pending(gated, type):
    client, bob, alice, _ = gated
    assert _send(client, alice, _wire(alice, bob, type=type)).json()["status"] == "pending"


def test_a_receipt_for_mail_bob_sent_goes_through(gated):
    client, bob, alice, _ = gated
    sent = _wire(bob, alice)
    assert _send(client, bob, sent).json()["status"] == "stored"

    receipt = _wire(alice, bob, type=MessageType.RECEIPT_READ, reply_to=sent["message_id"])
    assert _send(client, alice, receipt).json()["status"] != "pending"


def _answer(resp):
    body = resp.json()
    body.pop("message_id")
    return resp.status_code, body


def test_every_reason_gives_the_same_answer(gated):
    client, bob, alice, carol = gated
    unknown = _answer(_send(client, alice, _wire(alice, bob)))
    _allow(client, bob, alice, state="blocked")
    blocked = _answer(_send(client, alice, _wire(alice, bob)))
    _allow(client, bob, carol, key="not-carols-key")
    wrong_key = _answer(_send(client, carol, _wire(carol, bob)))

    assert unknown == blocked == wrong_key == (200, {"status": "pending", "delivered": False})


def test_a_bad_signature_is_refused_whether_or_not_the_recipient_is_gated(gated):
    client, bob, alice, carol = gated
    for to in (bob, carol):  # bob gated, carol open
        wire = _wire(alice, to)
        wire["signature"] = wire["signature"][::-1]
        assert _send(client, alice, wire).status_code == 400


def test_pending_mail_does_not_use_up_the_recipients_slots(gated):
    client, bob, alice, carol = gated
    _allow(client, bob, carol)
    for _ in range(101):  # past bob's 100/min
        assert _send(client, alice, _wire(alice, bob)).json()["status"] == "pending"

    assert _send(client, carol, _wire(carol, bob)).status_code == 200


def test_an_open_recipient_is_unaffected(client):
    bob = _register(client, "bob")
    alice = _register(client, "alice")
    assert _send(client, alice, _wire(alice, bob)).json()["status"] == "stored"


# --- WebSocket --------------------------------------------------------------


def test_over_websocket_a_stranger_gets_a_pending_ack(gated):
    client, bob, alice, _ = gated
    before = client.portal.call(lambda: _db(_counts))
    wire = _wire(alice, bob)

    with client.websocket_connect("/ws", headers=_auth(alice)) as ws:
        ws.send_json(wire)
        ack = ws.receive_json()

    assert ack == {"type": "ack", "message_id": wire["message_id"],
                   "status": "pending", "delivered": False}
    after = client.portal.call(lambda: _db(_counts))
    after.pop("agents"), before.pop("agents")  # last_seen on disconnect
    assert after == before


def test_over_websocket_an_online_gated_agent_gets_nothing_from_a_stranger(gated):
    client, bob, alice, carol = gated
    _allow(client, bob, carol)
    stranger, contact = _wire(alice, bob), _wire(carol, bob)

    with client.websocket_connect("/ws", headers=_auth(bob)) as bob_ws:
        with client.websocket_connect("/ws", headers=_auth(alice)) as ws:
            ws.send_json(stranger)
            assert ws.receive_json()["status"] == "pending"
        with client.websocket_connect("/ws", headers=_auth(carol)) as ws:
            ws.send_json(contact)
            ws.receive_json()
        assert bob_ws.receive_json()["message_id"] == contact["message_id"]


# --- demo widget --------------------------------------------------------------


def test_the_demo_widget_gets_pending_for_a_gated_agent(gated):
    client, bob, _, carol = gated
    demo = client.post("/api/v1/demo/session").json()

    gated_resp = client.post("/api/v1/demo/send", json={
        "session_id": demo["session_id"], "to_address": bob["address"], "message": "hi",
    })
    open_resp = client.post("/api/v1/demo/send", json={
        "session_id": demo["session_id"], "to_address": carol["address"], "message": "hi",
    })

    assert gated_resp.status_code == 200 and gated_resp.json()["status"] == "pending"
    assert open_resp.json()["status"] == "stored"
    inbox = client.get(f"/api/v1/inbox/{bob['address']}", headers=_auth(bob)).json()
    assert inbox["count"] == 0


# --- egress: mail stored before the gate closed -------------------------------


def _gate_now(client, bob):
    revision = _revision(client, bob)
    client.portal.call(lambda: _db(set_policy, bob["address"], "contacts",
                                   expected_revision=revision, set_by="admin"))


def _revision(client, bob):
    from uam.db.crud.inbound import get_policy

    async def rev(session):
        row = await get_policy(session, bob["address"])
        return row.revision if row else 0

    return client.portal.call(lambda: _db(rev))


def test_mail_stored_before_the_gate_closed_is_withheld_from_the_inbox(client):
    bob, alice, carol = (_register(client, n) for n in ("bob", "alice", "carol"))
    early = [_wire(alice, bob) for _ in range(3)]
    for wire in early:
        assert _send(client, alice, wire).json()["status"] == "stored"
    kept = _wire(carol, bob)
    assert _send(client, carol, kept).json()["status"] == "stored"

    _gate_now(client, bob)
    _allow(client, bob, carol)

    inbox = client.get(f"/api/v1/inbox/{bob['address']}", headers=_auth(bob)).json()
    assert [m["message_id"] for m in inbox["messages"]] == [kept["message_id"]]
    again = client.get(f"/api/v1/inbox/{bob['address']}", headers=_auth(bob)).json()
    assert again["count"] == 0  # withheld mail doesn't come back later


def test_withheld_mail_does_not_crowd_out_a_contacts_mail(client):
    bob, alice, carol = (_register(client, n) for n in ("bob", "alice", "carol"))
    _allow(client, bob, carol)
    for _ in range(3):
        _send(client, alice, _wire(alice, bob))
    kept = _wire(carol, bob)
    _send(client, carol, kept)
    _gate_now(client, bob)

    inbox = client.get(f"/api/v1/inbox/{bob['address']}", params={"limit": 2},
                       headers=_auth(bob)).json()
    ids = [m["message_id"] for m in inbox["messages"]]
    if not ids:  # the first page was all withheld; the next one isn't
        ids = [m["message_id"] for m in client.get(
            f"/api/v1/inbox/{bob['address']}", params={"limit": 2}, headers=_auth(bob)
        ).json()["messages"]]
    assert ids == [kept["message_id"]]


def test_the_websocket_drain_withholds_it_too(client):
    bob, alice, carol = (_register(client, n) for n in ("bob", "alice", "carol"))
    _send(client, alice, _wire(alice, bob))
    kept = _wire(carol, bob)
    _send(client, carol, kept)
    _gate_now(client, bob)
    _allow(client, bob, carol)

    with client.websocket_connect("/ws", headers=_auth(bob)) as ws:
        first = ws.receive_json()
    assert first["message_id"] == kept["message_id"]
    # Whether or not the drain marked carol's delivered before the socket
    # closed, alice's never comes out.
    inbox = client.get(f"/api/v1/inbox/{bob['address']}", headers=_auth(bob)).json()
    assert {m["message_id"] for m in inbox["messages"]} <= {kept["message_id"]}

"""The relay accepts only the message types the protocol defines.

``UAM_UNKNOWN_MESSAGE_TYPES`` chooses what happens to any other type:
``log`` (default) delivers it and logs a warning, so an operator can see
who sends custom types before turning on ``reject`` (400 /
``unknown_type``).
"""

from __future__ import annotations

import dataclasses
import logging

import pytest

from uam.protocol import MessageType, canonicalize, create_envelope, sign_message, to_wire_dict
from uam.protocol.envelope import _build_signable_dict

CUSTOM_TYPE = "x.custom.ping"


def _custom_type_envelope(sender, recipient) -> dict:
    """A correctly signed envelope whose type is not a MessageType."""
    base = create_envelope(
        from_address=sender["address"],
        to_address=recipient["address"],
        message_type=MessageType.MESSAGE,
        payload_plaintext=b"ping",
        signing_key=sender["signing_key"],
        recipient_verify_key=recipient["verify_key"],
    )
    unsigned = dataclasses.replace(base, type=CUSTOM_TYPE, signature="")
    signature = sign_message(canonicalize(_build_signable_dict(unsigned)), sender["signing_key"])
    return to_wire_dict(dataclasses.replace(unsigned, signature=signature))


def _send(client, sender, wire):
    return client.post(
        "/api/v1/send",
        json={"envelope": wire},
        headers={"Authorization": f"Bearer {sender['token']}"},
    )


def _inbox_ids(client, agent) -> list[str]:
    resp = client.get(
        f"/api/v1/inbox/{agent['address']}",
        headers={"Authorization": f"Bearer {agent['token']}"},
    )
    assert resp.status_code == 200, resp.text
    return [m["message_id"] for m in resp.json()["messages"]]


@pytest.fixture()
def enforce_types(client, monkeypatch):
    monkeypatch.setattr(client.app.state.settings, "unknown_message_types", "reject")


def test_unknown_type_rejected_over_rest_when_enforced(
    client, registered_agent_pair, enforce_types
):
    alice, bob = registered_agent_pair
    resp = _send(client, alice, _custom_type_envelope(alice, bob))

    assert resp.status_code == 400
    assert CUSTOM_TYPE in resp.json()["detail"]
    assert _inbox_ids(client, bob) == []


def test_unknown_type_rejected_over_websocket_when_enforced(
    client, registered_agent_pair, enforce_types
):
    alice, bob = registered_agent_pair
    with client.websocket_connect(
        "/ws", headers={"Authorization": f"Bearer {alice['token']}"}
    ) as ws:
        ws.send_json(_custom_type_envelope(alice, bob))
        reply = ws.receive_json()

    assert reply["error"] == "unknown_type"
    assert _inbox_ids(client, bob) == []


def test_unknown_type_delivered_and_logged_by_default(
    client, registered_agent_pair, caplog
):
    alice, bob = registered_agent_pair
    wire = _custom_type_envelope(alice, bob)

    with caplog.at_level(logging.WARNING, logger="uam.relay.policy"):
        resp = _send(client, alice, wire)

    assert resp.status_code == 200, resp.text
    assert _inbox_ids(client, bob) == [wire["message_id"]]
    assert any(
        CUSTOM_TYPE in r.getMessage() and alice["address"] in r.getMessage()
        for r in caplog.records
    )

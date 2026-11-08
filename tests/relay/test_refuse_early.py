"""A blocked or over-limit sender costs no database write."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from uam.protocol import MessageType, create_envelope, to_wire_dict


def _send(client, sender, wire):
    return client.post(
        "/api/v1/send",
        json={"envelope": wire},
        headers={"Authorization": f"Bearer {sender['token']}"},
    )


@pytest.fixture()
def no_dedup_writes():
    with (
        patch("uam.relay.routes.send.record_message_id", new_callable=AsyncMock) as rest,
        patch("uam.relay.ws.record_message_id", new_callable=AsyncMock) as ws,
    ):
        yield rest, ws
    rest.assert_not_called()
    ws.assert_not_called()


def test_rest_refuses_a_blocked_sender_before_the_database(
    client, app, registered_agent_pair, make_envelope, no_dedup_writes
):
    alice, bob = registered_agent_pair
    with patch.object(app.state.spam_filter, "is_blocked", return_value=True):
        resp = _send(client, alice, make_envelope(alice, bob))
    assert resp.status_code == 403
    assert resp.json()["detail"] == "Sender is blocked"


def test_rest_refuses_a_low_reputation_sender_before_the_database(
    client, app, registered_agent_pair, make_envelope, no_dedup_writes
):
    alice, bob = registered_agent_pair
    with patch.object(app.state.reputation_manager, "get_send_limit", return_value=0):
        resp = _send(client, alice, make_envelope(alice, bob))
    assert resp.status_code == 403


def test_rest_refuses_a_sender_over_its_limit_before_the_database(
    client, app, registered_agent_pair, make_envelope
):
    alice, bob = registered_agent_pair
    with patch.object(app.state.reputation_manager, "get_send_limit", return_value=1):
        assert _send(client, alice, make_envelope(alice, bob)).status_code == 200
        with patch(
            "uam.relay.routes.send.record_message_id", new_callable=AsyncMock
        ) as dedup:
            resp = _send(client, alice, make_envelope(alice, bob))
    assert resp.status_code == 429
    dedup.assert_not_called()


def test_the_early_check_uses_no_rate_limit_slot(
    client, app, registered_agent_pair, make_envelope
):
    alice, bob = registered_agent_pair
    with patch.object(app.state.reputation_manager, "get_send_limit", return_value=3):
        codes = [
            _send(client, alice, make_envelope(alice, bob)).status_code for _ in range(4)
        ]
    assert codes == [200, 200, 200, 429]


def test_receipts_are_not_held_to_the_message_limit(
    client, app, registered_agent_pair, make_envelope
):
    alice, bob = registered_agent_pair
    with patch.object(app.state.reputation_manager, "get_send_limit", return_value=1):
        assert _send(client, alice, make_envelope(alice, bob)).status_code == 200
        receipt = to_wire_dict(
            create_envelope(
                from_address=alice["address"],
                to_address=bob["address"],
                message_type=MessageType.RECEIPT_READ,
                payload_plaintext=b"{}",
                signing_key=alice["signing_key"],
                recipient_verify_key=bob["verify_key"],
            )
        )
        assert _send(client, alice, receipt).status_code == 200


def test_websocket_refuses_a_blocked_sender_before_the_database(
    client, app, registered_agent_pair, make_envelope, no_dedup_writes
):
    alice, bob = registered_agent_pair
    with client.websocket_connect(
        "/ws", headers={"Authorization": f"Bearer {alice['token']}"}
    ) as ws:
        with patch.object(app.state.spam_filter, "is_blocked", return_value=True):
            ws.send_json(make_envelope(alice, bob))
            frame = ws.receive_json()
    assert frame["error"] == "blocked"


def test_websocket_refuses_a_sender_over_its_limit_before_the_database(
    client, app, registered_agent_pair, make_envelope
):
    alice, bob = registered_agent_pair
    with patch.object(app.state.reputation_manager, "get_send_limit", return_value=1):
        with client.websocket_connect(
            "/ws", headers={"Authorization": f"Bearer {alice['token']}"}
        ) as ws:
            ws.send_json(make_envelope(alice, bob))
            assert ws.receive_json()["type"] == "ack"
            with patch(
                "uam.relay.ws.record_message_id", new_callable=AsyncMock
            ) as dedup:
                ws.send_json(make_envelope(alice, bob))
                frame = ws.receive_json()
    assert frame["error"] == "rate_limited"
    dedup.assert_not_called()

"""Every ingress path runs the same delivery checks (relay/policy.py).

A message the relay turns away must not be remembered as seen, so the
sender can send it again once the limit clears; and the demo widget's
send path gets the same blocklist and recipient limits as REST and WS.
"""

from __future__ import annotations

from uam.relay.rate_limit import SlidingWindowCounter


def _closed_recipient_limiter() -> SlidingWindowCounter:
    return SlidingWindowCounter(limit=0, window_seconds=60.0)


def _open_recipient_limiter() -> SlidingWindowCounter:
    return SlidingWindowCounter(limit=100, window_seconds=60.0)


def _inbox_ids(client, agent) -> list[str]:
    resp = client.get(
        f"/api/v1/inbox/{agent['address']}",
        headers={"Authorization": f"Bearer {agent['token']}"},
    )
    assert resp.status_code == 200, resp.text
    return [m["message_id"] for m in resp.json()["messages"]]


def test_ws_rejected_message_can_be_sent_again(
    client, registered_agent_pair, make_envelope
):
    alice, bob = registered_agent_pair
    wire = make_envelope(alice, bob)
    client.app.state.recipient_limiter = _closed_recipient_limiter()

    with client.websocket_connect(
        "/ws", headers={"Authorization": f"Bearer {alice['token']}"}
    ) as ws:
        ws.send_json(wire)
        assert ws.receive_json()["error"] == "rate_limited"

        client.app.state.recipient_limiter = _open_recipient_limiter()
        ws.send_json(wire)
        ack = ws.receive_json()

    assert ack["type"] == "ack"
    assert _inbox_ids(client, bob) == [wire["message_id"]]


def test_rest_rejected_message_can_be_sent_again(
    client, registered_agent_pair, make_envelope
):
    alice, bob = registered_agent_pair
    wire = make_envelope(alice, bob)
    headers = {"Authorization": f"Bearer {alice['token']}"}
    client.app.state.recipient_limiter = _closed_recipient_limiter()

    resp = client.post("/api/v1/send", json={"envelope": wire}, headers=headers)
    assert resp.status_code == 429

    client.app.state.recipient_limiter = _open_recipient_limiter()
    resp = client.post("/api/v1/send", json={"envelope": wire}, headers=headers)
    assert resp.status_code == 200, resp.text
    assert _inbox_ids(client, bob) == [wire["message_id"]]


def test_demo_send_respects_recipient_limit(client, registered_agent):
    session_id = client.post("/api/v1/demo/session").json()["session_id"]
    client.app.state.recipient_limiter = _closed_recipient_limiter()

    resp = client.post(
        "/api/v1/demo/send",
        json={
            "session_id": session_id,
            "to_address": registered_agent["address"],
            "message": "hello",
        },
    )
    assert resp.status_code == 429


def test_demo_send_from_blocked_address_rejected(client, registered_agent):
    session = client.post("/api/v1/demo/session").json()
    client.app.state.spam_filter._blocked_exact.add(session["address"].lower())

    resp = client.post(
        "/api/v1/demo/send",
        json={
            "session_id": session["session_id"],
            "to_address": registered_agent["address"],
            "message": "hello",
        },
    )
    assert resp.status_code == 403
    assert _inbox_ids(client, registered_agent) == []

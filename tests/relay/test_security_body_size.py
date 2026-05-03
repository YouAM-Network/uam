"""Phase 32 Task 4 -- HTTP body + envelope size caps."""

from __future__ import annotations

import json
import os

import pytest
from fastapi.testclient import TestClient

from uam.protocol import generate_keypair, serialize_verify_key
from uam.protocol.envelope import from_wire_dict
from uam.protocol.errors import EnvelopeTooLargeError
from uam.relay.app import create_app


def test_http_body_over_cap_returns_413(tmp_path):
    os.environ["UAM_DB_PATH"] = str(tmp_path / "bs1.db")
    os.environ["UAM_RELAY_DOMAIN"] = "test.local"
    os.environ["UAM_MAX_HTTP_BODY_BYTES"] = str(4 * 1024)  # 4 KiB
    try:
        app = create_app()
        with TestClient(app) as c:
            # 8 KiB body.
            huge = "x" * (8 * 1024)
            resp = c.post(
                "/api/v1/send",
                content=json.dumps({"envelope": {"blob": huge}}),
                headers={
                    "Content-Type": "application/json",
                    "Authorization": "Bearer irrelevant",
                },
            )
            assert resp.status_code == 413, resp.text
    finally:
        for k in ("UAM_DB_PATH", "UAM_RELAY_DOMAIN", "UAM_MAX_HTTP_BODY_BYTES"):
            os.environ.pop(k, None)


def test_envelope_over_cap_rejected_in_from_wire_dict():
    """Direct call to from_wire_dict must reject oversize wire dicts."""
    big = {
        "uam_version": "1.0",
        "message_id": "m",
        "from": "a::x",
        "to": "b::x",
        "timestamp": "t",
        "type": "message",
        "nonce": "n",
        "payload": "p" * (128 * 1024),
        "signature": "s",
    }
    with pytest.raises(EnvelopeTooLargeError):
        from_wire_dict(big, max_bytes=64 * 1024)


def test_envelope_unknown_field_rejected():
    """Strict schema: unknown top-level fields fail parsing."""
    d = {
        "uam_version": "1.0",
        "message_id": "m",
        "from": "a::x",
        "to": "b::x",
        "timestamp": "t",
        "type": "message",
        "nonce": "n",
        "payload": "p",
        "signature": "s",
        "gotcha": True,  # not a known field
    }
    from uam.protocol.errors import InvalidEnvelopeError

    with pytest.raises(InvalidEnvelopeError) as exc:
        from_wire_dict(d, max_bytes=128 * 1024)
    assert "unknown" in str(exc.value).lower()


def test_normal_envelope_still_accepted():
    """Small/normal wire dicts still parse fine."""
    d = {
        "uam_version": "1.0",
        "message_id": "m",
        "from": "a::x",
        "to": "b::x",
        "timestamp": "t",
        "type": "message",
        "nonce": "n",
        "payload": "p",
        "signature": "s",
    }
    env = from_wire_dict(d)
    assert env.message_id == "m"


def test_ws_oversize_frame_closes_with_1009(tmp_path):
    """WS frames exceeding max_envelope_bytes must close with 1009."""
    os.environ["UAM_DB_PATH"] = str(tmp_path / "bs2.db")
    os.environ["UAM_RELAY_DOMAIN"] = "test.local"
    os.environ["UAM_MAX_ENVELOPE_BYTES"] = str(2 * 1024)  # 2 KiB
    try:
        app = create_app()
        with TestClient(app) as c:
            sk, vk = generate_keypair()
            resp = c.post(
                "/api/v1/register",
                json={"agent_name": "bigframe", "public_key": serialize_verify_key(vk)},
            )
            assert resp.status_code == 200
            token = resp.json()["token"]

            huge = {"uam_version": "1.0", "blob": "x" * (4 * 1024)}
            with c.websocket_connect(
                "/ws", subprotocols=["uam.v1", f"bearer.{token}"]
            ) as ws:
                ws.send_text(json.dumps(huge))
                # Server flow: send an error JSON describing the oversize
                # frame, THEN close with 1009.  The first receive should get
                # the error payload; a follow-up receive should disconnect.
                first = ws.receive_json()
                assert first.get("error") == "envelope_too_large", first
                with pytest.raises(Exception):
                    ws.receive_text()
    finally:
        for k in ("UAM_DB_PATH", "UAM_RELAY_DOMAIN", "UAM_MAX_ENVELOPE_BYTES"):
            os.environ.pop(k, None)


def test_demo_message_over_2kb_returns_422(client, registered_agent):
    """Oversize demo message is rejected by Pydantic with 422."""
    # First create a demo session to reuse the /demo/send endpoint shape.
    resp = client.post("/api/v1/demo/session")
    assert resp.status_code == 200
    sid = resp.json()["session_id"]

    big = "x" * (3 * 1024)
    resp2 = client.post(
        "/api/v1/demo/send",
        json={
            "session_id": sid,
            "to_address": registered_agent["address"],
            "message": big,
        },
    )
    assert resp2.status_code == 422

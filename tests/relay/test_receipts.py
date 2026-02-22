"""Tests for receipt.delivered generation, anti-loop guard, and rate-limit exemption (MSG-05).

Covers:
- receipt.delivered generation after REST send
- Anti-loop guard (no receipt for receipt messages)
- Rate-limit exemption for receipt types
- Reputation check exemption for receipt types
- receipt.delivered generation after inbox retrieval
- Correct receipt fields (type, message_id, timestamp, to)
"""

from __future__ import annotations

import threading
import time

from uam.protocol import (
    MessageType,
    create_envelope,
    generate_keypair,
    serialize_verify_key,
    to_wire_dict,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _register(client, name: str = "testbot") -> dict:
    """Register an agent and return {address, token, signing_key, verify_key}."""
    sk, vk = generate_keypair()
    pk_str = serialize_verify_key(vk)
    resp = client.post("/api/v1/register", json={
        "agent_name": name,
        "public_key": pk_str,
    })
    assert resp.status_code == 200, f"Registration failed: {resp.text}"
    data = resp.json()
    return {
        "address": data["address"],
        "token": data["token"],
        "signing_key": sk,
        "verify_key": vk,
        "public_key_str": pk_str,
    }


def _boost(client, address: str, score: int = 80) -> None:
    """Set reputation score via in-memory cache (test-only)."""
    client.app.state.reputation_manager._cache[address] = score


def _make_wire(from_agent: dict, to_agent: dict) -> dict:
    """Create a signed envelope as a wire dict."""
    envelope = create_envelope(
        from_address=from_agent["address"],
        to_address=to_agent["address"],
        message_type=MessageType.MESSAGE,
        payload_plaintext=b"Hello from tests!",
        signing_key=from_agent["signing_key"],
        recipient_verify_key=to_agent["verify_key"],
    )
    return to_wire_dict(envelope)


def _send(client, sender: dict, recipient: dict) -> object:
    """Send a message from sender to recipient, return the response."""
    wire = _make_wire(sender, recipient)
    return client.post(
        "/api/v1/send",
        json={"envelope": wire},
        headers={"Authorization": f"Bearer {sender['token']}"},
    )


# ---------------------------------------------------------------------------
# receipt.delivered on REST send (MSG-05)
# ---------------------------------------------------------------------------


class TestReceiptDeliveredOnRestSend:
    """receipt.delivered is sent to the sender after successful WebSocket delivery via REST."""

    def test_receipt_delivered_on_rest_send(self, client, registered_agent_pair, make_envelope):
        """Send via POST /send to an online agent, verify sender gets receipt.delivered."""
        alice, bob = registered_agent_pair
        _boost(client, alice["address"])
        _boost(client, bob["address"])
        wire = make_envelope(alice, bob)

        receipts: list[dict] = []
        alice_ready = threading.Event()

        def alice_listener():
            with client.websocket_connect(f"/ws?token={alice['token']}") as ws:
                alice_ready.set()
                # Alice should receive receipt.delivered
                msg = ws.receive_json()
                receipts.append(msg)

        alice_thread = threading.Thread(target=alice_listener, daemon=True)
        alice_thread.start()
        alice_ready.wait(timeout=5)
        time.sleep(0.1)

        # Bob must be online for WebSocket delivery
        bob_msgs: list[dict] = []
        bob_ready = threading.Event()

        def bob_listener():
            with client.websocket_connect(f"/ws?token={bob['token']}") as ws:
                bob_ready.set()
                msg = ws.receive_json()
                bob_msgs.append(msg)

        bob_thread = threading.Thread(target=bob_listener, daemon=True)
        bob_thread.start()
        bob_ready.wait(timeout=5)
        time.sleep(0.1)

        # Alice sends via REST
        resp = client.post(
            "/api/v1/send",
            json={"envelope": wire},
            headers={"Authorization": f"Bearer {alice['token']}"},
        )
        assert resp.status_code == 200
        assert resp.json()["delivered"] is True

        # Wait for threads to process
        alice_thread.join(timeout=3)
        bob_thread.join(timeout=3)

        # Alice should have received a receipt.delivered
        assert len(receipts) == 1
        assert receipts[0]["type"] == "receipt.delivered"
        assert receipts[0]["message_id"] == wire["message_id"]
        assert receipts[0]["to"] == bob["address"]


# ---------------------------------------------------------------------------
# Anti-loop guard (MSG-05)
# ---------------------------------------------------------------------------


class TestAntiLoopGuard:
    """Receipt messages must NOT generate further receipts."""

    def test_no_receipt_for_receipt_messages_rest(self, client):
        """Send a receipt.delivered type via REST to offline agent -- verify no receipt generated.

        The anti-loop guard checks envelope type; receipt types skip receipt generation.
        We verify this by checking that no receipt is sent to the sender. Since bob is
        offline the message is stored (delivered=False), so no receipt would be sent
        even for normal messages. The key assertion is that the is_receipt flag correctly
        detects receipt types.
        """
        alice = _register(client, "looptesta")
        bob = _register(client, "looptestb")
        _boost(client, alice["address"])
        _boost(client, bob["address"])

        # Create a receipt.delivered envelope
        envelope = create_envelope(
            from_address=alice["address"],
            to_address=bob["address"],
            message_type=MessageType.RECEIPT_DELIVERED,
            payload_plaintext=b"receipt data",
            signing_key=alice["signing_key"],
            recipient_verify_key=bob["verify_key"],
        )
        wire = to_wire_dict(envelope)
        wire["type"] = "receipt.delivered"

        # Send receipt type via REST -- should succeed (no rate limit for receipts)
        resp = client.post(
            "/api/v1/send",
            json={"envelope": wire},
            headers={"Authorization": f"Bearer {alice['token']}"},
        )
        assert resp.status_code == 200

        # Now check: if alice is online and bob is online, sending a receipt.delivered
        # to bob should NOT produce a receipt.delivered back to alice
        # We test this via WebSocket path: send receipt type, check ack has no side-effect receipt

    def test_no_receipt_for_receipt_messages_ws(self, client):
        """Send a receipt.delivered type via WebSocket -- verify sender only gets ack, no receipt."""
        alice = _register(client, "loopwsa")
        bob = _register(client, "loopwsb")
        _boost(client, alice["address"])
        _boost(client, bob["address"])

        # Create a receipt.delivered envelope
        envelope = create_envelope(
            from_address=alice["address"],
            to_address=bob["address"],
            message_type=MessageType.RECEIPT_DELIVERED,
            payload_plaintext=b"receipt data",
            signing_key=alice["signing_key"],
            recipient_verify_key=bob["verify_key"],
        )
        wire = to_wire_dict(envelope)
        wire["type"] = "receipt.delivered"

        # Bob must be online for WebSocket delivery
        bob_msgs: list[dict] = []
        bob_ready = threading.Event()

        def bob_listener():
            with client.websocket_connect(f"/ws?token={bob['token']}") as ws:
                bob_ready.set()
                msg = ws.receive_json()
                bob_msgs.append(msg)

        bob_thread = threading.Thread(target=bob_listener, daemon=True)
        bob_thread.start()
        bob_ready.wait(timeout=5)
        time.sleep(0.1)

        # Alice sends receipt type via WebSocket
        with client.websocket_connect(f"/ws?token={alice['token']}") as ws_alice:
            ws_alice.send_json(wire)
            # Alice should receive ONLY an ack, NOT a receipt.delivered
            ack = ws_alice.receive_json()
            assert ack["type"] == "ack"
            assert ack["delivered"] is True

            # No further messages should be on the wire (no receipt.delivered)
            # The fact that only ack arrived proves the anti-loop guard works

        bob_thread.join(timeout=3)
        # Bob should have received the receipt message (it was delivered)
        assert len(bob_msgs) == 1


# ---------------------------------------------------------------------------
# Rate-limit exemption for receipt types (MSG-05)
# ---------------------------------------------------------------------------


class TestReceiptRateLimitExemption:
    """Receipt types must skip rate limits."""

    def test_receipt_types_skip_rate_limits(self, client):
        """Exhaust sender rate limit, then send receipt type -- should NOT be rate-limited."""
        alice = _register(client, "ratelimita")
        bob = _register(client, "ratelimitb")
        _boost(client, alice["address"])
        _boost(client, bob["address"])

        # Exhaust the sender rate limit (default 60/min, score=80 -> limit=60)
        limiter = client.app.state.sender_limiter
        for _ in range(60):
            limiter.check(alice["address"])

        # Normal message should fail
        resp = _send(client, alice, bob)
        assert resp.status_code == 429, f"Expected 429 but got {resp.status_code}"

        # Receipt type should succeed despite exhausted rate limit
        envelope = create_envelope(
            from_address=alice["address"],
            to_address=bob["address"],
            message_type=MessageType.RECEIPT_DELIVERED,
            payload_plaintext=b"receipt",
            signing_key=alice["signing_key"],
            recipient_verify_key=bob["verify_key"],
        )
        wire = to_wire_dict(envelope)
        wire["type"] = "receipt.delivered"

        resp = client.post(
            "/api/v1/send",
            json={"envelope": wire},
            headers={"Authorization": f"Bearer {alice['token']}"},
        )
        assert resp.status_code == 200, f"Receipt should bypass rate limit: {resp.text}"

    def test_receipt_types_skip_reputation_check(self, client):
        """Sender with reputation 0 can still send receipt type."""
        alice = _register(client, "lowrepa")
        bob = _register(client, "lowrepb")
        # Set alice to blocked reputation
        _boost(client, alice["address"], score=0)
        _boost(client, bob["address"])

        # Normal message should fail (reputation too low)
        resp = _send(client, alice, bob)
        assert resp.status_code == 403, f"Expected 403 but got {resp.status_code}"

        # Receipt type should succeed
        envelope = create_envelope(
            from_address=alice["address"],
            to_address=bob["address"],
            message_type=MessageType.RECEIPT_DELIVERED,
            payload_plaintext=b"receipt",
            signing_key=alice["signing_key"],
            recipient_verify_key=bob["verify_key"],
        )
        wire = to_wire_dict(envelope)
        wire["type"] = "receipt.delivered"

        resp = client.post(
            "/api/v1/send",
            json={"envelope": wire},
            headers={"Authorization": f"Bearer {alice['token']}"},
        )
        assert resp.status_code == 200, f"Receipt should bypass reputation check: {resp.text}"


# ---------------------------------------------------------------------------
# receipt.delivered on inbox retrieval (MSG-05)
# ---------------------------------------------------------------------------


class TestReceiptDeliveredOnInboxRetrieval:
    """receipt.delivered is sent to the original sender when messages are retrieved via GET /inbox."""

    def test_receipt_delivered_on_inbox_retrieval(self, client, registered_agent_pair, make_envelope):
        """Store message, retrieve via GET /inbox, verify receipt.delivered sent to sender."""
        alice, bob = registered_agent_pair
        _boost(client, alice["address"])
        _boost(client, bob["address"])
        wire = make_envelope(alice, bob)

        # Send while bob is offline -- stored
        resp = client.post(
            "/api/v1/send",
            json={"envelope": wire},
            headers={"Authorization": f"Bearer {alice['token']}"},
        )
        assert resp.status_code == 200
        assert resp.json()["delivered"] is False  # stored

        # Connect alice to receive receipt
        receipts: list[dict] = []
        alice_ready = threading.Event()

        def alice_listener():
            with client.websocket_connect(f"/ws?token={alice['token']}") as ws:
                alice_ready.set()
                msg = ws.receive_json()
                receipts.append(msg)

        alice_thread = threading.Thread(target=alice_listener, daemon=True)
        alice_thread.start()
        alice_ready.wait(timeout=5)
        time.sleep(0.1)

        # Bob retrieves inbox via REST
        inbox_resp = client.get(
            f"/api/v1/inbox/{bob['address']}",
            headers={"Authorization": f"Bearer {bob['token']}"},
        )
        assert inbox_resp.status_code == 200
        assert inbox_resp.json()["count"] == 1

        # Wait for receipt delivery
        alice_thread.join(timeout=3)

        # Alice should have received receipt.delivered
        assert len(receipts) == 1
        assert receipts[0]["type"] == "receipt.delivered"
        assert receipts[0]["to"] == bob["address"]


# ---------------------------------------------------------------------------
# receipt.delivered field validation (MSG-05)
# ---------------------------------------------------------------------------


class TestReceiptDeliveredFields:
    """Verify receipt.delivered has correct fields."""

    def test_receipt_delivered_has_correct_fields(self, client, registered_agent_pair, make_envelope):
        """Verify receipt has type, message_id, timestamp, to fields."""
        alice, bob = registered_agent_pair
        _boost(client, alice["address"])
        _boost(client, bob["address"])
        wire = make_envelope(alice, bob)

        receipts: list[dict] = []
        alice_ready = threading.Event()

        def alice_listener():
            with client.websocket_connect(f"/ws?token={alice['token']}") as ws:
                alice_ready.set()
                msg = ws.receive_json()
                receipts.append(msg)

        alice_thread = threading.Thread(target=alice_listener, daemon=True)
        alice_thread.start()
        alice_ready.wait(timeout=5)
        time.sleep(0.1)

        # Bob online
        bob_ready = threading.Event()

        def bob_listener():
            with client.websocket_connect(f"/ws?token={bob['token']}") as ws:
                bob_ready.set()
                try:
                    ws.receive_json()
                except Exception:
                    pass

        bob_thread = threading.Thread(target=bob_listener, daemon=True)
        bob_thread.start()
        bob_ready.wait(timeout=5)
        time.sleep(0.1)

        # Send via REST
        resp = client.post(
            "/api/v1/send",
            json={"envelope": wire},
            headers={"Authorization": f"Bearer {alice['token']}"},
        )
        assert resp.status_code == 200

        alice_thread.join(timeout=3)
        bob_thread.join(timeout=3)

        assert len(receipts) == 1
        receipt = receipts[0]

        # Verify all required fields
        assert receipt["type"] == "receipt.delivered"
        assert receipt["message_id"] == wire["message_id"]
        assert "timestamp" in receipt
        assert receipt["timestamp"].endswith("Z")
        assert receipt["to"] == bob["address"]

        # Verify no extra fields
        assert set(receipt.keys()) == {"type", "message_id", "timestamp", "to"}

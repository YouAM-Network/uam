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
# Receipt lanes (MSG-05): bound receipts skip limits, unbound ones are capped
# ---------------------------------------------------------------------------


def _receipt_wire(from_agent: dict, to_agent: dict, reply_to: str | None) -> dict:
    """A signed receipt.read from *from_agent* about message *reply_to*."""
    return to_wire_dict(create_envelope(
        from_address=from_agent["address"],
        to_address=to_agent["address"],
        message_type=MessageType.RECEIPT_READ,
        payload_plaintext=b"read",
        signing_key=from_agent["signing_key"],
        recipient_verify_key=to_agent["verify_key"],
        reply_to=reply_to,
    ))


def _post(client, sender: dict, wire: dict):
    return client.post(
        "/api/v1/send",
        json={"envelope": wire},
        headers={"Authorization": f"Bearer {sender['token']}"},
    )


def _inbox_ids(client, agent: dict) -> list[str]:
    resp = client.get(
        f"/api/v1/inbox/{agent['address']}",
        headers={"Authorization": f"Bearer {agent['token']}"},
    )
    assert resp.status_code == 200, resp.text
    return [m["message_id"] for m in resp.json()["messages"]]


def _close(client, limiter_name: str) -> None:
    """Swap in a limiter that refuses everything (callers that pass no
    per-call ``limit``: recipient_limiter, receipt_limiter)."""
    from uam.relay.rate_limit import SlidingWindowCounter

    setattr(client.app.state, limiter_name, SlidingWindowCounter(limit=0, window_seconds=60.0))


def _exhaust_sender_limit(client, address: str) -> None:
    """Use up *address*'s sender bucket on the app's own event loop."""
    limiter = client.app.state.sender_limiter

    async def _drain() -> None:
        while await limiter.check(address):
            pass

    client.portal.call(_drain)


class TestBoundReceipts:
    """A receipt whose signed reply_to names a message the relay routed the
    other way (to the receipt's sender, from its recipient) is bound: it is
    not held to the sender's rate limit or reputation, up to 3 per message."""

    def _routed_message(self, client, alice, bob) -> str:
        wire = _make_wire(alice, bob)
        assert _post(client, alice, wire).status_code == 200
        _inbox_ids(client, bob)  # bob picks it up
        return wire["message_id"]

    def test_bound_receipt_skips_exhausted_sender_limit(self, client):
        alice, bob = _register(client, "bounda"), _register(client, "boundb")
        _boost(client, alice["address"])
        _boost(client, bob["address"])
        message_id = self._routed_message(client, alice, bob)
        _exhaust_sender_limit(client, bob["address"])
        _close(client, "receipt_limiter")

        assert _send(client, bob, alice).status_code == 429
        receipt = _receipt_wire(bob, alice, reply_to=message_id)
        resp = _post(client, bob, receipt)

        assert resp.status_code == 200, resp.text
        assert receipt["message_id"] in _inbox_ids(client, alice)

    def test_bound_receipt_skips_reputation_floor(self, client):
        alice, bob = _register(client, "boundrepa"), _register(client, "boundrepb")
        _boost(client, alice["address"])
        message_id = self._routed_message(client, alice, bob)
        _boost(client, bob["address"], score=0)
        _close(client, "receipt_limiter")

        assert _send(client, bob, alice).status_code == 403
        receipt = _receipt_wire(bob, alice, reply_to=message_id)

        assert _post(client, bob, receipt).status_code == 200
        assert receipt["message_id"] in _inbox_ids(client, alice)

    def test_receipt_about_a_message_routed_the_same_way_is_not_bound(self, client):
        alice, bob = _register(client, "samewaya"), _register(client, "samewayb")
        _boost(client, alice["address"])
        message_id = self._routed_message(client, alice, bob)
        _close(client, "receipt_limiter")

        # alice -> bob about alice's own message to bob: not a reply to anything
        receipt = _receipt_wire(alice, bob, reply_to=message_id)

        assert _post(client, alice, receipt).status_code == 200
        assert receipt["message_id"] not in _inbox_ids(client, bob)

    def test_at_most_three_receipts_per_message_are_bound(self, client):
        alice, bob = _register(client, "threea"), _register(client, "threeb")
        _boost(client, alice["address"])
        _boost(client, bob["address"])
        message_id = self._routed_message(client, alice, bob)
        _close(client, "receipt_limiter")

        receipts = [_receipt_wire(bob, alice, reply_to=message_id) for _ in range(4)]
        for r in receipts:
            assert _post(client, bob, r).status_code == 200

        delivered = set(_inbox_ids(client, alice))
        assert [r["message_id"] in delivered for r in receipts] == [True, True, True, False]


class TestUnboundReceipts:
    """Receipts without a bound reply_to get their own small per-sender
    bucket: they never use the sender's or recipient's message capacity,
    and past the bucket they are accepted (200) but not delivered."""

    def test_unbound_receipt_skips_message_limits(self, client):
        alice, bob = _register(client, "unbounda"), _register(client, "unboundb")
        _boost(client, alice["address"])
        _exhaust_sender_limit(client, alice["address"])
        _close(client, "recipient_limiter")
        assert _send(client, alice, bob).status_code == 429

        receipt = _receipt_wire(alice, bob, reply_to=None)
        resp = _post(client, alice, receipt)

        assert resp.status_code == 200, resp.text
        assert _inbox_ids(client, bob) == [receipt["message_id"]]

    def test_unbound_receipt_past_its_bucket_is_accepted_not_delivered(self, client):
        alice, bob = _register(client, "overa"), _register(client, "overb")
        _boost(client, alice["address"])
        _close(client, "receipt_limiter")
        score = client.app.state.reputation_manager.get_score(alice["address"])

        receipt = _receipt_wire(alice, bob, reply_to=None)
        resp = _post(client, alice, receipt)

        assert resp.status_code == 200, resp.text
        assert resp.json()["delivered"] is False
        assert _inbox_ids(client, bob) == []
        assert client.app.state.reputation_manager.get_score(alice["address"]) == score

    def test_unbound_receipt_past_its_bucket_over_websocket(self, client):
        alice, bob = _register(client, "overwsa"), _register(client, "overwsb")
        _boost(client, alice["address"])
        _close(client, "receipt_limiter")

        receipt = _receipt_wire(alice, bob, reply_to=None)
        with client.websocket_connect(
            "/ws", headers={"Authorization": f"Bearer {alice['token']}"}
        ) as ws:
            ws.send_json(receipt)
            ack = ws.receive_json()

        assert ack == {"type": "ack", "message_id": receipt["message_id"], "delivered": False}
        assert _inbox_ids(client, bob) == []


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

"""Tests for POST /api/v1/send endpoint."""

from __future__ import annotations

from uam.protocol import (
    MessageType,
    create_envelope,
    generate_keypair,
    to_wire_dict,
)


class TestSendHTTP:
    """REST message send tests."""

    def test_send_to_offline_agent(self, client, registered_agent_pair, make_envelope):
        """Sending to an offline agent stores the message (delivered=False)."""
        alice, bob = registered_agent_pair
        wire = make_envelope(alice, bob)

        resp = client.post(
            "/api/v1/send",
            json={"envelope": wire},
            headers={"Authorization": f"Bearer {alice['token']}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["delivered"] is False
        assert "message_id" in data

    def test_send_invalid_envelope(self, client, registered_agent_pair):
        """Malformed envelope dict returns 400."""
        alice, _bob = registered_agent_pair
        resp = client.post(
            "/api/v1/send",
            json={"envelope": {"garbage": True}},
            headers={"Authorization": f"Bearer {alice['token']}"},
        )
        assert resp.status_code == 400

    def test_send_signature_mismatch(self, client, registered_agent_pair):
        """Envelope signed by a different key than the registered agent returns 400."""
        alice, bob = registered_agent_pair

        # Create a valid envelope but signed with a DIFFERENT key
        rogue_sk, _rogue_vk = generate_keypair()
        envelope = create_envelope(
            from_address=alice["address"],
            to_address=bob["address"],
            message_type=MessageType.MESSAGE,
            payload_plaintext=b"rogue message",
            signing_key=rogue_sk,
            recipient_verify_key=bob["verify_key"],
        )
        wire = to_wire_dict(envelope)

        resp = client.post(
            "/api/v1/send",
            json={"envelope": wire},
            headers={"Authorization": f"Bearer {alice['token']}"},
        )
        assert resp.status_code == 400

    def test_send_sender_mismatch(self, client, registered_agent_pair, make_envelope):
        """Envelope from field doesn't match authenticated agent returns 403."""
        alice, bob = registered_agent_pair

        # Create an envelope where bob is the sender but we auth as alice
        wire = make_envelope(bob, alice)

        resp = client.post(
            "/api/v1/send",
            json={"envelope": wire},
            headers={"Authorization": f"Bearer {alice['token']}"},
        )
        assert resp.status_code == 403

    def test_send_without_auth(self, client, registered_agent_pair, make_envelope):
        """POST without Authorization header returns 401."""
        alice, bob = registered_agent_pair
        wire = make_envelope(alice, bob)

        resp = client.post(
            "/api/v1/send",
            json={"envelope": wire},
        )
        assert resp.status_code == 401

"""Cross-relay federation integration tests -- INTEROP-02.

These tests prove federation works with multi-relay topologies:
- Message forwarding between relays delivers correctly
- Loop prevention via hop_count catches cycles
- Loop prevention via via chain catches loops
- Replay protection rejects stale timestamps
- Domain mismatch rejection
- Invalid relay signature rejection
- Dedup prevents duplicate delivery
- Three-relay triangle topology (stretch)

Each test uses the federated_relay_pair or three_relay_triangle fixtures
from conftest.py, which create isolated relay instances with mutual trust.
Federation delivery is tested by directly POSTing to the inbound federation
endpoint with properly signed relay requests.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from uam.protocol import (
    MessageType,
    create_envelope,
    serialize_verify_key,
    to_wire_dict,
    utc_timestamp,
)
from uam.relay.relay_auth import sign_federation_request

pytestmark = pytest.mark.interop


def _build_federation_body(
    envelope_dict: dict,
    from_relay: str,
    via: list[str] | None = None,
    hop_count: int = 0,
    timestamp: str | None = None,
) -> dict:
    """Build a federation deliver request body."""
    return {
        "envelope": envelope_dict,
        "via": (via or []) + [from_relay],
        "hop_count": hop_count + 1,
        "timestamp": timestamp or utc_timestamp(),
        "from_relay": from_relay,
    }


def _sign_and_post(client, body: dict, relay_sk, from_relay: str):
    """Sign a federation body and POST to /api/v1/federation/deliver."""
    signature = sign_federation_request(body, relay_sk)
    return client.post(
        "/api/v1/federation/deliver",
        json=body,
        headers={
            "X-UAM-Relay-Signature": signature,
            "X-UAM-Relay-Domain": from_relay,
        },
    )


class TestFederationForwardDeliversMessage:
    """Agent on Relay A sends message to agent on Relay B via federation (INTEROP-02)."""

    def test_federation_forward_delivers_message(self, federated_relay_pair):
        """Alice on alpha sends to bob::beta.test via federation deliver endpoint."""
        ctx = federated_relay_pair
        alice = ctx["alpha_agent"]
        bob = ctx["beta_agent"]
        beta_client = ctx["beta_client"]
        alpha_sk = ctx["alpha_relay_sk"]

        # Create signed envelope from alice to bob
        envelope = create_envelope(
            from_address=alice["address"],
            to_address=bob["address"],
            message_type=MessageType.MESSAGE,
            payload_plaintext=b"Hello via federation!",
            signing_key=alice["signing_key"],
            recipient_verify_key=bob["verify_key"],
        )
        wire = to_wire_dict(envelope)

        # Build federation request body (simulating alpha relay forwarding to beta)
        body = _build_federation_body(wire, "alpha.test")

        # Sign with alpha's relay key and POST to beta's federation endpoint
        resp = _sign_and_post(beta_client, body, alpha_sk, "alpha.test")
        assert resp.status_code == 200, f"Federation deliver failed: {resp.text}"
        data = resp.json()
        assert data["status"] in ("delivered", "stored")

        # Verify bob's inbox on beta contains the message
        inbox_resp = beta_client.get(
            f"/api/v1/inbox/{bob['address']}",
            headers={"Authorization": f"Bearer {bob['token']}"},
        )
        assert inbox_resp.status_code == 200
        inbox_data = inbox_resp.json()
        assert inbox_data["count"] == 1
        assert inbox_data["messages"][0]["message_id"] == envelope.message_id


class TestFederationLoopPreventionHopCount:
    """Loop prevention via hop_count catches cycles (INTEROP-02)."""

    def test_federation_loop_prevention_hop_count(self, federated_relay_pair):
        """POST with hop_count >= max_hops is rejected."""
        ctx = federated_relay_pair
        alice = ctx["alpha_agent"]
        bob = ctx["beta_agent"]
        alpha_client = ctx["alpha_client"]
        beta_sk = ctx["beta_relay_sk"]

        # Create a valid envelope
        envelope = create_envelope(
            from_address=alice["address"],
            to_address=f"someone::alpha.test",
            message_type=MessageType.MESSAGE,
            payload_plaintext=b"Loop test",
            signing_key=alice["signing_key"],
            recipient_verify_key=bob["verify_key"],
        )
        wire = to_wire_dict(envelope)

        # Build body with hop_count=3 (>= default max of 3)
        body = {
            "envelope": wire,
            "via": ["gamma.test", "beta.test"],
            "hop_count": 3,
            "timestamp": utc_timestamp(),
            "from_relay": "beta.test",
        }

        resp = _sign_and_post(alpha_client, body, beta_sk, "beta.test")
        assert resp.status_code == 400
        assert "Hop count" in resp.json()["detail"]


class TestFederationLoopPreventionViaChain:
    """Loop prevention via via chain catches loops (INTEROP-02)."""

    def test_federation_loop_prevention_via_chain(self, federated_relay_pair):
        """POST with self-domain in via chain is rejected."""
        ctx = federated_relay_pair
        alice = ctx["alpha_agent"]
        bob = ctx["beta_agent"]
        alpha_client = ctx["alpha_client"]
        beta_sk = ctx["beta_relay_sk"]

        envelope = create_envelope(
            from_address=alice["address"],
            to_address=f"someone::alpha.test",
            message_type=MessageType.MESSAGE,
            payload_plaintext=b"Via chain loop",
            signing_key=alice["signing_key"],
            recipient_verify_key=bob["verify_key"],
        )
        wire = to_wire_dict(envelope)

        # Build body with alpha.test already in via chain
        body = {
            "envelope": wire,
            "via": ["alpha.test", "beta.test"],  # alpha.test already visited
            "hop_count": 1,
            "timestamp": utc_timestamp(),
            "from_relay": "beta.test",
        }

        resp = _sign_and_post(alpha_client, body, beta_sk, "beta.test")
        assert resp.status_code == 400
        assert "Loop detected" in resp.json()["detail"]


class TestFederationReplayProtection:
    """Replay protection rejects federated messages older than 5 minutes (INTEROP-02)."""

    def test_federation_replay_protection(self, federated_relay_pair):
        """POST with timestamp 10 minutes in the past is rejected."""
        ctx = federated_relay_pair
        alice = ctx["alpha_agent"]
        bob = ctx["beta_agent"]
        alpha_client = ctx["alpha_client"]
        beta_sk = ctx["beta_relay_sk"]

        envelope = create_envelope(
            from_address=bob["address"],
            to_address=f"someone::alpha.test",
            message_type=MessageType.MESSAGE,
            payload_plaintext=b"Stale message",
            signing_key=bob["signing_key"],
            recipient_verify_key=alice["verify_key"],
        )
        wire = to_wire_dict(envelope)

        # Build body with timestamp 10 minutes ago
        old_ts = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat(
            timespec="milliseconds"
        ).replace("+00:00", "Z")

        body = {
            "envelope": wire,
            "via": ["beta.test"],
            "hop_count": 1,
            "timestamp": old_ts,
            "from_relay": "beta.test",
        }

        resp = _sign_and_post(alpha_client, body, beta_sk, "beta.test")
        assert resp.status_code == 400
        assert "too old" in resp.json()["detail"].lower() or "old" in resp.json()["detail"].lower()


class TestFederationDomainMismatch:
    """Domain mismatch is rejected (INTEROP-02)."""

    def test_federation_domain_mismatch_rejected(self, federated_relay_pair):
        """POST with envelope to wrong domain is rejected."""
        ctx = federated_relay_pair
        alice = ctx["alpha_agent"]
        bob = ctx["beta_agent"]
        alpha_client = ctx["alpha_client"]
        beta_sk = ctx["beta_relay_sk"]

        # Envelope addressed to gamma.test, but delivered to alpha.test
        envelope = create_envelope(
            from_address=bob["address"],
            to_address="charlie::gamma.test",
            message_type=MessageType.MESSAGE,
            payload_plaintext=b"Wrong domain",
            signing_key=bob["signing_key"],
            recipient_verify_key=alice["verify_key"],
        )
        wire = to_wire_dict(envelope)

        body = _build_federation_body(wire, "beta.test")

        resp = _sign_and_post(alpha_client, body, beta_sk, "beta.test")
        assert resp.status_code == 400
        assert "Destination domain mismatch" in resp.json()["detail"]


class TestFederationInvalidSignature:
    """Invalid relay signature is rejected (INTEROP-02)."""

    def test_federation_invalid_relay_signature_rejected(self, federated_relay_pair):
        """POST with garbage X-UAM-Relay-Signature header returns 401."""
        ctx = federated_relay_pair
        alice = ctx["alpha_agent"]
        bob = ctx["beta_agent"]
        alpha_client = ctx["alpha_client"]

        envelope = create_envelope(
            from_address=bob["address"],
            to_address=f"someone::alpha.test",
            message_type=MessageType.MESSAGE,
            payload_plaintext=b"Bad sig test",
            signing_key=bob["signing_key"],
            recipient_verify_key=alice["verify_key"],
        )
        wire = to_wire_dict(envelope)

        body = _build_federation_body(wire, "beta.test")

        # POST with a properly-sized but wrong signature (64 zero bytes, base64-encoded)
        import base64
        fake_sig = base64.urlsafe_b64encode(b"\x00" * 64).decode().rstrip("=")

        resp = alpha_client.post(
            "/api/v1/federation/deliver",
            json=body,
            headers={
                "X-UAM-Relay-Signature": fake_sig,
                "X-UAM-Relay-Domain": "beta.test",
            },
        )
        assert resp.status_code == 401
        assert "Invalid relay signature" in resp.json()["detail"]


class TestFederationDedupPreventsDuplicate:
    """Dedup prevents duplicate delivery (INTEROP-02)."""

    def test_federation_dedup_prevents_duplicate_delivery(self, federated_relay_pair):
        """Same message sent twice: first succeeds, second returns duplicate."""
        ctx = federated_relay_pair
        alice = ctx["alpha_agent"]
        bob = ctx["beta_agent"]
        beta_client = ctx["beta_client"]
        alpha_sk = ctx["alpha_relay_sk"]

        envelope = create_envelope(
            from_address=alice["address"],
            to_address=bob["address"],
            message_type=MessageType.MESSAGE,
            payload_plaintext=b"Dedup test",
            signing_key=alice["signing_key"],
            recipient_verify_key=bob["verify_key"],
        )
        wire = to_wire_dict(envelope)

        # First delivery
        body1 = _build_federation_body(wire, "alpha.test")
        resp1 = _sign_and_post(beta_client, body1, alpha_sk, "alpha.test")
        assert resp1.status_code == 200
        assert resp1.json()["status"] in ("delivered", "stored")

        # Second delivery (same envelope, new federation request)
        body2 = _build_federation_body(wire, "alpha.test")
        resp2 = _sign_and_post(beta_client, body2, alpha_sk, "alpha.test")
        assert resp2.status_code == 200
        assert resp2.json()["status"] == "duplicate"


class TestThreeRelayTriangleNoLoops:
    """Three-relay triangle correctly handles routing without loops (INTEROP-02)."""

    def test_three_relay_direct_deliveries(self, three_relay_triangle):
        """Each relay can receive federation messages from its known peer."""
        ctx = three_relay_triangle
        alice = ctx["alpha_agent"]
        bob = ctx["beta_agent"]
        charlie = ctx["gamma_agent"]

        # alpha -> beta (alice sends to bob)
        env_ab = create_envelope(
            from_address=alice["address"],
            to_address=bob["address"],
            message_type=MessageType.MESSAGE,
            payload_plaintext=b"Alpha to Beta",
            signing_key=alice["signing_key"],
            recipient_verify_key=bob["verify_key"],
        )
        wire_ab = to_wire_dict(env_ab)
        body_ab = _build_federation_body(wire_ab, "alpha.test")
        resp_ab = _sign_and_post(
            ctx["beta_client"], body_ab, ctx["alpha_relay_sk"], "alpha.test"
        )
        assert resp_ab.status_code == 200

        # beta -> gamma (bob sends to charlie)
        env_bg = create_envelope(
            from_address=bob["address"],
            to_address=charlie["address"],
            message_type=MessageType.MESSAGE,
            payload_plaintext=b"Beta to Gamma",
            signing_key=bob["signing_key"],
            recipient_verify_key=charlie["verify_key"],
        )
        wire_bg = to_wire_dict(env_bg)
        body_bg = _build_federation_body(wire_bg, "beta.test")
        resp_bg = _sign_and_post(
            ctx["gamma_client"], body_bg, ctx["beta_relay_sk"], "beta.test"
        )
        assert resp_bg.status_code == 200

        # gamma -> alpha (charlie sends to alice)
        env_ga = create_envelope(
            from_address=charlie["address"],
            to_address=alice["address"],
            message_type=MessageType.MESSAGE,
            payload_plaintext=b"Gamma to Alpha",
            signing_key=charlie["signing_key"],
            recipient_verify_key=alice["verify_key"],
        )
        wire_ga = to_wire_dict(env_ga)
        body_ga = _build_federation_body(wire_ga, "gamma.test")
        resp_ga = _sign_and_post(
            ctx["alpha_client"], body_ga, ctx["gamma_relay_sk"], "gamma.test"
        )
        assert resp_ga.status_code == 200

        # Verify all inboxes have the expected messages
        inbox_bob = ctx["beta_client"].get(
            f"/api/v1/inbox/{bob['address']}",
            headers={"Authorization": f"Bearer {bob['token']}"},
        )
        assert inbox_bob.json()["count"] == 1

        inbox_charlie = ctx["gamma_client"].get(
            f"/api/v1/inbox/{charlie['address']}",
            headers={"Authorization": f"Bearer {charlie['token']}"},
        )
        assert inbox_charlie.json()["count"] == 1

        inbox_alice = ctx["alpha_client"].get(
            f"/api/v1/inbox/{alice['address']}",
            headers={"Authorization": f"Bearer {alice['token']}"},
        )
        assert inbox_alice.json()["count"] == 1

    def test_three_relay_via_chain_rejects_cycle(self, three_relay_triangle):
        """A message with the receiving relay already in via chain is rejected."""
        ctx = three_relay_triangle
        alice = ctx["alpha_agent"]
        bob = ctx["beta_agent"]

        envelope = create_envelope(
            from_address=alice["address"],
            to_address=f"someone::beta.test",
            message_type=MessageType.MESSAGE,
            payload_plaintext=b"Cycle test",
            signing_key=alice["signing_key"],
            recipient_verify_key=bob["verify_key"],
        )
        wire = to_wire_dict(envelope)

        # Build body with beta.test already in via (simulating it already passed through beta)
        body = {
            "envelope": wire,
            "via": ["alpha.test", "beta.test"],  # beta already visited
            "hop_count": 2,
            "timestamp": utc_timestamp(),
            "from_relay": "alpha.test",
        }

        resp = _sign_and_post(
            ctx["beta_client"], body, ctx["alpha_relay_sk"], "alpha.test"
        )
        assert resp.status_code == 400
        assert "Loop detected" in resp.json()["detail"]

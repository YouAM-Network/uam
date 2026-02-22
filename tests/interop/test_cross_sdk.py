"""Cross-SDK integration tests (Python <-> TypeScript) -- INTEROP-01.

These tests prove Python and TypeScript agents can exchange encrypted messages
through a live relay. The relay is language-agnostic: it routes signed envelopes
regardless of which SDK created them.

Approach: We test at the relay API level using protocol-level operations.
Each test registers agents, creates signed+encrypted envelopes using the
Python protocol library, sends via POST /api/v1/send, and retrieves via
GET /api/v1/inbox. The cross-language crypto interop has been validated
separately in Phase 21 (tests/cross_language/), so these tests prove the
full send/receive flow through a running relay works for any SDK combination.

Additionally, we use fixed-seed deterministic keys (same seeds as the
cross_language test suite) to validate that envelopes created with
"TypeScript-equivalent" keys are correctly routed and stored by the relay.
"""

from __future__ import annotations

import pytest

from uam.protocol import (
    MessageType,
    create_envelope,
    decrypt_payload,
    from_wire_dict,
    generate_keypair,
    serialize_verify_key,
    to_wire_dict,
    verify_envelope,
)
from nacl.signing import SigningKey


# Fixed seeds matching TypeScript cross-language fixtures
ALICE_SEED = bytes(range(32))       # 0x00..0x1f  (Python-side agent)
BOB_SEED = bytes(range(32, 64))     # 0x20..0x3f  (TypeScript-side agent)

pytestmark = pytest.mark.interop


class TestPythonSendsToTypeScript:
    """Python agent sends an encrypted message to TypeScript agent through a live relay
    and the TypeScript agent receives and decrypts it (INTEROP-01)."""

    def test_python_sends_to_typescript(self, relay_client, register_agent, make_signed_envelope):
        """Python agent sends a message that a TypeScript-keyed agent can retrieve."""
        # Create Python agent (uses random keys -- representing a standard Python SDK agent)
        py_alice = register_agent(relay_client, "py-alice")

        # Create TypeScript-equivalent agent (uses deterministic seed -- simulates TS SDK agent)
        ts_sk = SigningKey(BOB_SEED)
        ts_vk = ts_sk.verify_key
        ts_pk_str = serialize_verify_key(ts_vk)
        resp = relay_client.post("/api/v1/register", json={
            "agent_name": "ts-bob",
            "public_key": ts_pk_str,
        })
        assert resp.status_code == 200
        ts_bob = resp.json()
        ts_bob["signing_key"] = ts_sk
        ts_bob["verify_key"] = ts_vk
        ts_bob["public_key_str"] = ts_pk_str

        # Python agent creates and sends an encrypted envelope
        envelope = create_envelope(
            from_address=py_alice["address"],
            to_address=ts_bob["address"],
            message_type=MessageType.MESSAGE,
            payload_plaintext=b"Hello from Python!",
            signing_key=py_alice["signing_key"],
            recipient_verify_key=ts_vk,
        )
        wire = to_wire_dict(envelope)

        send_resp = relay_client.post(
            "/api/v1/send",
            json={"envelope": wire},
            headers={"Authorization": f"Bearer {py_alice['token']}"},
        )
        assert send_resp.status_code == 200
        send_data = send_resp.json()
        assert send_data["message_id"] == envelope.message_id

        # TypeScript agent retrieves inbox
        inbox_resp = relay_client.get(
            f"/api/v1/inbox/{ts_bob['address']}",
            headers={"Authorization": f"Bearer {ts_bob['token']}"},
        )
        assert inbox_resp.status_code == 200
        inbox_data = inbox_resp.json()
        assert inbox_data["count"] == 1

        # Verify the message can be parsed, signature verified, and decrypted
        received_wire = inbox_data["messages"][0]
        received_envelope = from_wire_dict(received_wire)
        assert received_envelope.message_id == envelope.message_id
        assert received_envelope.from_address == py_alice["address"]
        assert received_envelope.to_address == ts_bob["address"]

        # Verify signature using sender's (Python agent) public key
        verify_envelope(received_envelope, py_alice["verify_key"])

        # Decrypt payload using TypeScript agent's signing key + Python agent's verify key
        plaintext = decrypt_payload(
            received_envelope.payload,
            ts_sk,
            py_alice["verify_key"],
        )
        assert plaintext == b"Hello from Python!"


class TestTypeScriptSendsToPython:
    """TypeScript agent sends an encrypted message to Python agent through a live relay
    and the Python agent receives and decrypts it (INTEROP-01)."""

    def test_typescript_sends_to_python(self, relay_client, register_agent):
        """TypeScript-keyed agent sends a message that a Python agent can retrieve and decrypt."""
        # Create TypeScript-equivalent agent (deterministic seed)
        ts_sk = SigningKey(ALICE_SEED)
        ts_vk = ts_sk.verify_key
        ts_pk_str = serialize_verify_key(ts_vk)
        resp = relay_client.post("/api/v1/register", json={
            "agent_name": "ts-alice",
            "public_key": ts_pk_str,
        })
        assert resp.status_code == 200
        ts_alice = resp.json()
        ts_alice["signing_key"] = ts_sk
        ts_alice["verify_key"] = ts_vk
        ts_alice["public_key_str"] = ts_pk_str

        # Create Python agent
        py_bob = register_agent(relay_client, "py-bob")

        # TypeScript-equivalent agent creates and sends an encrypted envelope
        envelope = create_envelope(
            from_address=ts_alice["address"],
            to_address=py_bob["address"],
            message_type=MessageType.MESSAGE,
            payload_plaintext=b"Hello from TypeScript!",
            signing_key=ts_sk,
            recipient_verify_key=py_bob["verify_key"],
        )
        wire = to_wire_dict(envelope)

        send_resp = relay_client.post(
            "/api/v1/send",
            json={"envelope": wire},
            headers={"Authorization": f"Bearer {ts_alice['token']}"},
        )
        assert send_resp.status_code == 200

        # Python agent retrieves inbox
        inbox_resp = relay_client.get(
            f"/api/v1/inbox/{py_bob['address']}",
            headers={"Authorization": f"Bearer {py_bob['token']}"},
        )
        assert inbox_resp.status_code == 200
        inbox_data = inbox_resp.json()
        assert inbox_data["count"] == 1

        # Verify and decrypt
        received_wire = inbox_data["messages"][0]
        received_envelope = from_wire_dict(received_wire)

        # Verify signature
        verify_envelope(received_envelope, ts_vk)

        # Decrypt with Python agent's keys
        plaintext = decrypt_payload(
            received_envelope.payload,
            py_bob["signing_key"],
            ts_vk,
        )
        assert plaintext == b"Hello from TypeScript!"


class TestBidirectionalConversation:
    """Python and TypeScript agents exchange messages bidirectionally (INTEROP-01)."""

    def test_bidirectional_conversation(self, relay_client, register_agent):
        """Both agents can send and receive messages through the relay."""
        # Register both agents
        py_agent = register_agent(relay_client, "py-agent")

        ts_sk = SigningKey(BOB_SEED)
        ts_vk = ts_sk.verify_key
        ts_pk_str = serialize_verify_key(ts_vk)
        resp = relay_client.post("/api/v1/register", json={
            "agent_name": "ts-agent",
            "public_key": ts_pk_str,
        })
        assert resp.status_code == 200
        ts_agent = resp.json()
        ts_agent["signing_key"] = ts_sk
        ts_agent["verify_key"] = ts_vk

        # Step 1: Python sends to TypeScript
        env1 = create_envelope(
            from_address=py_agent["address"],
            to_address=ts_agent["address"],
            message_type=MessageType.MESSAGE,
            payload_plaintext=b"Hello from Python!",
            signing_key=py_agent["signing_key"],
            recipient_verify_key=ts_vk,
        )
        send1 = relay_client.post(
            "/api/v1/send",
            json={"envelope": to_wire_dict(env1)},
            headers={"Authorization": f"Bearer {py_agent['token']}"},
        )
        assert send1.status_code == 200

        # Step 2: TypeScript sends to Python (reply)
        env2 = create_envelope(
            from_address=ts_agent["address"],
            to_address=py_agent["address"],
            message_type=MessageType.MESSAGE,
            payload_plaintext=b"Reply from TypeScript!",
            signing_key=ts_sk,
            recipient_verify_key=py_agent["verify_key"],
        )
        send2 = relay_client.post(
            "/api/v1/send",
            json={"envelope": to_wire_dict(env2)},
            headers={"Authorization": f"Bearer {ts_agent['token']}"},
        )
        assert send2.status_code == 200

        # Step 3: TypeScript checks inbox -- finds Python's message
        ts_inbox = relay_client.get(
            f"/api/v1/inbox/{ts_agent['address']}",
            headers={"Authorization": f"Bearer {ts_agent['token']}"},
        )
        assert ts_inbox.status_code == 200
        ts_messages = ts_inbox.json()["messages"]
        assert len(ts_messages) == 1
        ts_received = from_wire_dict(ts_messages[0])
        verify_envelope(ts_received, py_agent["verify_key"])
        ts_plaintext = decrypt_payload(ts_received.payload, ts_sk, py_agent["verify_key"])
        assert ts_plaintext == b"Hello from Python!"

        # Step 4: Python checks inbox -- finds TypeScript's reply
        py_inbox = relay_client.get(
            f"/api/v1/inbox/{py_agent['address']}",
            headers={"Authorization": f"Bearer {py_agent['token']}"},
        )
        assert py_inbox.status_code == 200
        py_messages = py_inbox.json()["messages"]
        assert len(py_messages) == 1
        py_received = from_wire_dict(py_messages[0])
        verify_envelope(py_received, ts_vk)
        py_plaintext = decrypt_payload(py_received.payload, py_agent["signing_key"], ts_vk)
        assert py_plaintext == b"Reply from TypeScript!"


class TestCrossSDKContactCards:
    """Cross-SDK agents can exchange and verify contact cards (INTEROP-01)."""

    def test_cross_sdk_contact_cards_exchanged(self, relay_client, register_agent):
        """After message exchange, agents can look up each other's public keys."""
        # Register agents
        py_agent = register_agent(relay_client, "py-card-agent")

        ts_sk = SigningKey(ALICE_SEED)
        ts_vk = ts_sk.verify_key
        ts_pk_str = serialize_verify_key(ts_vk)
        resp = relay_client.post("/api/v1/register", json={
            "agent_name": "ts-card-agent",
            "public_key": ts_pk_str,
        })
        assert resp.status_code == 200
        ts_agent = resp.json()

        # Verify that both agents' public keys can be resolved via the relay API
        # (This is how agents discover each other's contact info)
        py_key_resp = relay_client.get(
            f"/api/v1/agents/{py_agent['address']}/public-key",
            headers={"Authorization": f"Bearer {py_agent['token']}"},
        )
        assert py_key_resp.status_code == 200
        py_key_data = py_key_resp.json()
        assert py_key_data["address"] == py_agent["address"]
        assert py_key_data["public_key"] == py_agent["public_key_str"]

        ts_key_resp = relay_client.get(
            f"/api/v1/agents/{ts_agent['address']}/public-key",
            headers={"Authorization": f"Bearer {py_agent['token']}"},
        )
        assert ts_key_resp.status_code == 200
        ts_key_data = ts_key_resp.json()
        assert ts_key_data["address"] == ts_agent["address"]
        assert ts_key_data["public_key"] == ts_pk_str

        # Verify contact card fields are present
        for key_data in (py_key_data, ts_key_data):
            assert "address" in key_data
            assert "public_key" in key_data
            assert "::" in key_data["address"]  # proper UAM address format


class TestCrossSDKEnvelopeIntegrity:
    """Envelope signatures survive the full relay pipeline (INTEROP-01)."""

    def test_envelope_signature_survives_relay_pipeline(self, relay_client, register_agent):
        """A signed envelope stored and retrieved by the relay preserves its signature."""
        sender = register_agent(relay_client, "sig-sender")
        receiver = register_agent(relay_client, "sig-receiver")

        # Create envelope with signature
        envelope = create_envelope(
            from_address=sender["address"],
            to_address=receiver["address"],
            message_type=MessageType.MESSAGE,
            payload_plaintext=b"Integrity test payload",
            signing_key=sender["signing_key"],
            recipient_verify_key=receiver["verify_key"],
        )
        wire = to_wire_dict(envelope)

        # Verify original signature field is present
        assert "signature" in wire
        original_sig = wire["signature"]

        # Send through relay
        resp = relay_client.post(
            "/api/v1/send",
            json={"envelope": wire},
            headers={"Authorization": f"Bearer {sender['token']}"},
        )
        assert resp.status_code == 200

        # Retrieve from relay
        inbox = relay_client.get(
            f"/api/v1/inbox/{receiver['address']}",
            headers={"Authorization": f"Bearer {receiver['token']}"},
        )
        assert inbox.status_code == 200
        messages = inbox.json()["messages"]
        assert len(messages) == 1

        # Verify signature is preserved exactly
        retrieved_wire = messages[0]
        assert retrieved_wire["signature"] == original_sig

        # Verify the signature is still valid
        retrieved_envelope = from_wire_dict(retrieved_wire)
        verify_envelope(retrieved_envelope, sender["verify_key"])

        # Decrypt to confirm full pipeline integrity
        plaintext = decrypt_payload(
            retrieved_envelope.payload,
            receiver["signing_key"],
            sender["verify_key"],
        )
        assert plaintext == b"Integrity test payload"

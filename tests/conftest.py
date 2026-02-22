"""Shared test fixtures for UAM protocol tests."""

from __future__ import annotations

import pytest
from nacl.signing import SigningKey

from uam.protocol.address import Address, parse_address
from uam.protocol.contact import create_contact_card
from uam.protocol.envelope import MessageEnvelope, create_envelope
from uam.protocol.types import MessageType


@pytest.fixture()
def keypair():
    """Return an Ed25519 (signing_key, verify_key) tuple."""
    sk = SigningKey.generate()
    return sk, sk.verify_key


@pytest.fixture()
def keypair_pair():
    """Return two keypairs -- (alice_sk, alice_vk), (bob_sk, bob_vk)."""
    alice_sk = SigningKey.generate()
    bob_sk = SigningKey.generate()
    return (alice_sk, alice_sk.verify_key), (bob_sk, bob_sk.verify_key)


@pytest.fixture()
def sample_address_str() -> str:
    return "alice::youam.network"


@pytest.fixture()
def sample_address() -> Address:
    return parse_address("alice::youam.network")


@pytest.fixture()
def bob_address_str() -> str:
    return "bob::youam.network"


@pytest.fixture()
def sample_envelope(keypair_pair) -> MessageEnvelope:
    """Create a valid signed+encrypted envelope (alice -> bob)."""
    (alice_sk, _), (_, bob_vk) = keypair_pair
    return create_envelope(
        from_address="alice::youam.network",
        to_address="bob::youam.network",
        message_type=MessageType.MESSAGE,
        payload_plaintext=b"Hello Bob!",
        signing_key=alice_sk,
        recipient_verify_key=bob_vk,
    )


@pytest.fixture()
def sample_contact_card(keypair):
    """Create a valid signed contact card."""
    sk, _ = keypair
    return create_contact_card(
        address="alice::youam.network",
        display_name="Alice Agent",
        relay="wss://relay.youam.network",
        signing_key=sk,
        description="A helpful agent",
    )

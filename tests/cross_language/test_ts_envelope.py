"""Python tests that verify TypeScript-generated fixtures.

Proves that Python can:
1. Verify envelope signatures created by TypeScript
2. Decrypt payloads encrypted by TypeScript (both NaCl Box and SealedBox)
3. Parse and verify contact cards created by TypeScript
4. Derive identical keys from the same seed as TypeScript
"""
from nacl.signing import SigningKey

from uam.protocol.crypto import (
    decrypt_payload,
    decrypt_payload_anonymous,
    serialize_verify_key,
    public_key_fingerprint,
)
from uam.protocol.envelope import from_wire_dict, verify_envelope
from uam.protocol.contact import contact_card_from_dict
from uam.protocol.types import b64_decode


# Fixed seeds (same as TypeScript and Python generators)
ALICE_SEED = bytes(range(32))       # 0x00..0x1f
BOB_SEED = bytes(range(32, 64))     # 0x20..0x3f


def test_key_derivation_matches(ts_fixtures):
    """Verify that Python derives the same keys from the same seeds."""
    keys = ts_fixtures["keys"]

    alice_sk = SigningKey(ALICE_SEED)
    assert serialize_verify_key(alice_sk.verify_key) == keys["alice"]["verify_key_b64"]
    assert public_key_fingerprint(alice_sk.verify_key) == keys["alice"]["fingerprint"]

    bob_sk = SigningKey(BOB_SEED)
    assert serialize_verify_key(bob_sk.verify_key) == keys["bob"]["verify_key_b64"]
    assert public_key_fingerprint(bob_sk.verify_key) == keys["bob"]["fingerprint"]


def test_verify_ts_envelope(ts_fixtures):
    """Verify a TypeScript-created message envelope."""
    envelope_dict = ts_fixtures["envelope"]
    keys = ts_fixtures["keys"]

    # Reconstruct keys from seeds
    alice_sk = SigningKey(ALICE_SEED)
    bob_sk = SigningKey(BOB_SEED)

    # Parse wire format
    envelope = from_wire_dict(envelope_dict)
    assert envelope.from_address == "alice::test.example.com"
    assert envelope.to_address == "bob::test.example.com"
    assert envelope.type == "message"
    assert envelope.media_type == "text/plain"

    # Verify signature using alice's verify key
    verify_envelope(envelope, alice_sk.verify_key)

    # Decrypt payload using bob's signing key and alice's verify key
    plaintext = decrypt_payload(envelope.payload, bob_sk, alice_sk.verify_key)
    assert plaintext == b"Hello from TypeScript!"


def test_verify_ts_contact_card(ts_fixtures):
    """Verify a TypeScript-created contact card."""
    card_dict = ts_fixtures["contact_card"]

    # Parse with verification (verify=True is default)
    card = contact_card_from_dict(card_dict)
    assert card.address == "alice::test.example.com"
    assert card.display_name == "Alice (TypeScript)"
    assert card.relay == "wss://relay.test.example.com/ws"
    assert card.description == "Test agent created by TypeScript"


def test_decrypt_ts_box_payload(ts_fixtures):
    """Decrypt a TypeScript-encrypted NaCl Box payload."""
    fixture = ts_fixtures["box_payload"]

    alice_sk = SigningKey(ALICE_SEED)
    bob_sk = SigningKey(BOB_SEED)

    plaintext = decrypt_payload(
        fixture["ciphertext_b64"],
        bob_sk,
        alice_sk.verify_key,
    )
    assert plaintext == b"Box encrypted by TypeScript"


def test_decrypt_ts_sealedbox_payload(ts_fixtures):
    """Decrypt a TypeScript-encrypted SealedBox payload."""
    fixture = ts_fixtures["sealedbox_payload"]

    bob_sk = SigningKey(BOB_SEED)

    plaintext = decrypt_payload_anonymous(
        fixture["ciphertext_b64"],
        bob_sk,
    )
    assert plaintext == b"SealedBox encrypted by TypeScript"

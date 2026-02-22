"""Generate deterministic test fixtures for cross-language verification.

Uses fixed seeds so outputs are reproducible. TypeScript tests load these
fixtures and verify they can verify signatures and decrypt payloads.
"""
import json
import sys
from pathlib import Path

# Add project src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / "src"))

from nacl.signing import SigningKey
from uam.protocol.crypto import (
    serialize_signing_key, serialize_verify_key, public_key_fingerprint,
    encrypt_payload, encrypt_payload_anonymous, canonicalize, sign_message,
)
from uam.protocol.envelope import create_envelope, to_wire_dict
from uam.protocol.contact import create_contact_card, contact_card_to_dict
from uam.protocol.types import b64_encode, MessageType

FIXTURES_DIR = Path(__file__).parent / "fixtures"
FIXTURES_DIR.mkdir(exist_ok=True)

# Fixed seeds (32 bytes each) -- deterministic key generation
ALICE_SEED = bytes(range(32))           # 0x00..0x1f
BOB_SEED = bytes(range(32, 64))         # 0x20..0x3f

alice_sk = SigningKey(ALICE_SEED)
bob_sk = SigningKey(BOB_SEED)

# 1. Export keys
keys = {
    "alice": {
        "seed_b64": b64_encode(ALICE_SEED),
        "signing_key_b64": serialize_signing_key(alice_sk),
        "verify_key_b64": serialize_verify_key(alice_sk.verify_key),
        "fingerprint": public_key_fingerprint(alice_sk.verify_key),
    },
    "bob": {
        "seed_b64": b64_encode(BOB_SEED),
        "signing_key_b64": serialize_signing_key(bob_sk),
        "verify_key_b64": serialize_verify_key(bob_sk.verify_key),
        "fingerprint": public_key_fingerprint(bob_sk.verify_key),
    },
}
(FIXTURES_DIR / "python-keys.json").write_text(json.dumps(keys, indent=2))

# 2. Create envelope (alice -> bob, regular message)
envelope = create_envelope(
    from_address="alice::test.example.com",
    to_address="bob::test.example.com",
    message_type=MessageType.MESSAGE,
    payload_plaintext=b"Hello from Python!",
    signing_key=alice_sk,
    recipient_verify_key=bob_sk.verify_key,
    media_type="text/plain",
)
envelope_wire = to_wire_dict(envelope)
(FIXTURES_DIR / "python-envelope.json").write_text(json.dumps(envelope_wire, indent=2))

# 3. Create handshake request envelope (alice -> bob, SealedBox)
hs_envelope = create_envelope(
    from_address="alice::test.example.com",
    to_address="bob::test.example.com",
    message_type=MessageType.HANDSHAKE_REQUEST,
    payload_plaintext=b'{"type":"handshake","from":"alice"}',
    signing_key=alice_sk,
    recipient_verify_key=bob_sk.verify_key,
)
hs_wire = to_wire_dict(hs_envelope)
(FIXTURES_DIR / "python-handshake-envelope.json").write_text(json.dumps(hs_wire, indent=2))

# 4. Create contact card
card = create_contact_card(
    address="alice::test.example.com",
    display_name="Alice (Python)",
    relay="wss://relay.test.example.com/ws",
    signing_key=alice_sk,
    description="Test agent created by Python",
)
card_dict = contact_card_to_dict(card)
(FIXTURES_DIR / "python-contact-card.json").write_text(json.dumps(card_dict, indent=2))

# 5. Create NaCl Box encrypted payload (alice -> bob) with known plaintext
box_ciphertext = encrypt_payload(
    b"Box encrypted by Python",
    alice_sk,
    bob_sk.verify_key,
)
box_fixture = {
    "plaintext": "Box encrypted by Python",
    "ciphertext_b64": box_ciphertext,
    "sender_seed_b64": b64_encode(ALICE_SEED),
    "recipient_seed_b64": b64_encode(BOB_SEED),
}
(FIXTURES_DIR / "python-box-payload.json").write_text(json.dumps(box_fixture, indent=2))

# 6. Create SealedBox encrypted payload (-> bob)
sealed_ciphertext = encrypt_payload_anonymous(
    b"SealedBox encrypted by Python",
    bob_sk.verify_key,
)
sealed_fixture = {
    "plaintext": "SealedBox encrypted by Python",
    "ciphertext_b64": sealed_ciphertext,
    "recipient_seed_b64": b64_encode(BOB_SEED),
}
(FIXTURES_DIR / "python-sealedbox-payload.json").write_text(json.dumps(sealed_fixture, indent=2))

print(f"Generated fixtures in {FIXTURES_DIR}/")

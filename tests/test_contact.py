"""Tests for uam.protocol.contact module."""

from __future__ import annotations

import dataclasses

import pytest

from uam.protocol.contact import (
    ContactCard,
    _build_signable_dict,
    contact_card_from_dict,
    contact_card_to_dict,
    create_contact_card,
    verify_contact_card,
)
from uam.protocol.crypto import (
    deserialize_verify_key,
    generate_keypair,
    public_key_fingerprint,
    serialize_verify_key,
)
from uam.protocol.errors import (
    InvalidAddressError,
    InvalidContactCardError,
    SignatureVerificationError,
)


# ---------------------------------------------------------------------------
# v1.0 Regression (lock current signature behavior before Phase 14 changes)
# ---------------------------------------------------------------------------


class TestV10Regression:
    """Guard that v1.0 contact card signatures remain valid after v1.1 changes."""

    def test_v10_contact_card_signature_still_valid(self, keypair):
        """Create, serialize, verify, deserialize, verify -- full round-trip."""
        sk, _ = keypair
        card = create_contact_card(
            address="alice::youam.network",
            display_name="Alice",
            relay="wss://relay.youam.network",
            signing_key=sk,
        )
        # Verify the in-memory card
        verify_contact_card(card)

        # Serialize and verify the dict round-trip
        d = contact_card_to_dict(card)
        verify_contact_card(card)

        # Deserialize (which verifies by default) and assert equal
        restored = contact_card_from_dict(d)
        assert restored.address == card.address
        assert restored.display_name == card.display_name
        assert restored.relay == card.relay
        assert restored.public_key == card.public_key
        assert restored.signature == card.signature
        verify_contact_card(restored)

    def test_v10_contact_card_dict_keys(self, keypair):
        """v1.1 cards created via create_contact_card include new fields,
        but the signature is still stable (verified by the test above).
        Cards created via create_contact_card now include payload_formats
        and fingerprint by default."""
        sk, _ = keypair
        card = create_contact_card(
            address="alice::youam.network",
            display_name="Alice",
            relay="wss://relay.youam.network",
            signing_key=sk,
        )
        d = contact_card_to_dict(card)
        # v1.1 cards have payload_formats and fingerprint
        expected_keys = {
            "version", "address", "display_name", "relay",
            "public_key", "signature", "payload_formats", "fingerprint",
        }
        assert set(d.keys()) == expected_keys


# ---------------------------------------------------------------------------
# Creation
# ---------------------------------------------------------------------------

class TestCreation:
    def test_all_fields_present(self, keypair):
        sk, vk = keypair
        card = create_contact_card(
            address="alice::youam.network",
            display_name="Alice Agent",
            relay="wss://relay.youam.network",
            signing_key=sk,
        )
        assert card.version is not None
        assert card.address is not None
        assert card.display_name is not None
        assert card.relay is not None
        assert card.public_key is not None
        assert card.signature is not None

    def test_version_is_0_1(self, keypair):
        sk, _ = keypair
        card = create_contact_card(
            address="alice::youam.network",
            display_name="Alice",
            relay="wss://relay.youam.network",
            signing_key=sk,
        )
        assert card.version == "0.1"

    def test_public_key_matches(self, keypair):
        sk, vk = keypair
        card = create_contact_card(
            address="alice::youam.network",
            display_name="Alice",
            relay="wss://relay.youam.network",
            signing_key=sk,
        )
        assert card.public_key == serialize_verify_key(vk)

    def test_address_preserved(self, keypair):
        sk, _ = keypair
        card = create_contact_card(
            address="alice::youam.network",
            display_name="Alice",
            relay="wss://relay.youam.network",
            signing_key=sk,
        )
        assert card.address == "alice::youam.network"

    def test_optional_fields_none_when_not_provided(self, keypair):
        sk, _ = keypair
        card = create_contact_card(
            address="alice::youam.network",
            display_name="Alice",
            relay="wss://relay.youam.network",
            signing_key=sk,
        )
        assert card.description is None
        assert card.system is None
        assert card.connection_endpoint is None
        assert card.verified_domain is None

    def test_optional_fields_present_when_provided(self, keypair):
        sk, _ = keypair
        card = create_contact_card(
            address="alice::youam.network",
            display_name="Alice",
            relay="wss://relay.youam.network",
            signing_key=sk,
            description="A helpful agent",
            system="openai",
            connection_endpoint="https://alice.example.com",
        )
        assert card.description == "A helpful agent"
        assert card.system == "openai"
        assert card.connection_endpoint == "https://alice.example.com"


# ---------------------------------------------------------------------------
# Signing and verification
# ---------------------------------------------------------------------------

class TestSigningVerification:
    def test_verify_succeeds(self, sample_contact_card):
        verify_contact_card(sample_contact_card)  # should not raise

    def test_tampered_display_name_fails(self, sample_contact_card):
        tampered = dataclasses.replace(sample_contact_card, display_name="Evil Agent")
        with pytest.raises(SignatureVerificationError):
            verify_contact_card(tampered)

    def test_tampered_address_fails(self, keypair):
        sk, _ = keypair
        card = create_contact_card(
            address="alice::youam.network",
            display_name="Alice",
            relay="wss://relay.youam.network",
            signing_key=sk,
        )
        tampered = dataclasses.replace(card, address="eve::youam.network")
        with pytest.raises(SignatureVerificationError):
            verify_contact_card(tampered)

    def test_self_verifying(self, keypair):
        """Card embeds public_key so any recipient can verify without external key."""
        sk, _ = keypair
        card = create_contact_card(
            address="alice::youam.network",
            display_name="Alice",
            relay="wss://relay.youam.network",
            signing_key=sk,
        )
        # verify_contact_card uses the embedded public_key, not an external key
        verify_contact_card(card)


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------

class TestSerialization:
    def test_roundtrip(self, sample_contact_card):
        d = contact_card_to_dict(sample_contact_card)
        restored = contact_card_from_dict(d)
        assert restored == sample_contact_card

    def test_excludes_none_optionals(self, keypair):
        sk, _ = keypair
        card = create_contact_card(
            address="alice::youam.network",
            display_name="Alice",
            relay="wss://relay.youam.network",
            signing_key=sk,
        )
        d = contact_card_to_dict(card)
        assert "description" not in d
        assert "system" not in d
        assert "connection_endpoint" not in d

    def test_missing_required_raises(self):
        with pytest.raises(InvalidContactCardError):
            contact_card_from_dict({"version": "0.1"}, verify=False)

    def test_from_dict_verifies_by_default(self, sample_contact_card):
        d = contact_card_to_dict(sample_contact_card)
        d["display_name"] = "Tampered"  # invalidate signature
        with pytest.raises(SignatureVerificationError):
            contact_card_from_dict(d)

    def test_from_dict_verify_false_skips_check(self, sample_contact_card):
        d = contact_card_to_dict(sample_contact_card)
        d["display_name"] = "Tampered"
        card = contact_card_from_dict(d, verify=False)  # should not raise
        assert card.display_name == "Tampered"

    def test_includes_optional_when_present(self, sample_contact_card):
        d = contact_card_to_dict(sample_contact_card)
        # sample_contact_card has description="A helpful agent"
        assert d["description"] == "A helpful agent"


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

class TestValidation:
    def test_invalid_address_raises(self, keypair):
        sk, _ = keypair
        with pytest.raises(InvalidAddressError):
            create_contact_card(
                address="invalid-address",
                display_name="Alice",
                relay="wss://relay.youam.network",
                signing_key=sk,
            )


# ---------------------------------------------------------------------------
# Immutability
# ---------------------------------------------------------------------------

class TestImmutability:
    def test_contact_card_is_frozen(self, sample_contact_card):
        with pytest.raises(AttributeError):
            sample_contact_card.display_name = "Tampered"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Verified domain (DNS-06)
# ---------------------------------------------------------------------------


class TestVerifiedDomain:
    def test_none_produces_same_signature(self, keypair):
        """ContactCard with verified_domain=None should produce the same
        signature as one created without the field at all (backward compat)."""
        sk, _ = keypair
        card_without = create_contact_card(
            address="alice::youam.network",
            display_name="Alice",
            relay="wss://relay.youam.network",
            signing_key=sk,
        )
        card_with_none = create_contact_card(
            address="alice::youam.network",
            display_name="Alice",
            relay="wss://relay.youam.network",
            signing_key=sk,
            verified_domain=None,
        )
        assert card_without.signature == card_with_none.signature

    def test_verified_domain_in_signable_dict(self, keypair):
        """ContactCard with verified_domain set should include it in the
        signable dict, changing the signature."""
        sk, _ = keypair
        card_none = create_contact_card(
            address="alice::youam.network",
            display_name="Alice",
            relay="wss://relay.youam.network",
            signing_key=sk,
            verified_domain=None,
        )
        card_domain = create_contact_card(
            address="alice::youam.network",
            display_name="Alice",
            relay="wss://relay.youam.network",
            signing_key=sk,
            verified_domain="example.com",
        )
        d_none = _build_signable_dict(card_none)
        d_domain = _build_signable_dict(card_domain)
        assert "verified_domain" not in d_none
        assert d_domain["verified_domain"] == "example.com"
        # Signatures must differ
        assert card_none.signature != card_domain.signature

    def test_verified_domain_roundtrip(self, keypair):
        """Serialization and deserialization preserves verified_domain."""
        sk, _ = keypair
        card = create_contact_card(
            address="alice::youam.network",
            display_name="Alice",
            relay="wss://relay.youam.network",
            signing_key=sk,
            verified_domain="example.com",
        )
        d = contact_card_to_dict(card)
        assert d["verified_domain"] == "example.com"
        restored = contact_card_from_dict(d)
        assert restored.verified_domain == "example.com"
        assert restored == card

    def test_verified_domain_none_roundtrip(self, keypair):
        """Cards without verified_domain serialize without the field."""
        sk, _ = keypair
        card = create_contact_card(
            address="alice::youam.network",
            display_name="Alice",
            relay="wss://relay.youam.network",
            signing_key=sk,
        )
        d = contact_card_to_dict(card)
        assert "verified_domain" not in d
        restored = contact_card_from_dict(d)
        assert restored.verified_domain is None
        assert restored == card

    def test_verified_card_verifies(self, keypair):
        """A card with verified_domain passes signature verification."""
        sk, _ = keypair
        card = create_contact_card(
            address="alice::youam.network",
            display_name="Alice",
            relay="wss://relay.youam.network",
            signing_key=sk,
            verified_domain="example.com",
        )
        verify_contact_card(card)  # should not raise


# ---------------------------------------------------------------------------
# Payload formats (CARD-02)
# ---------------------------------------------------------------------------


class TestPayloadFormats:
    def test_default_payload_formats(self, keypair):
        """Cards default to text/plain + text/markdown."""
        sk, _ = keypair
        card = create_contact_card(
            address="alice::youam.network",
            display_name="Alice",
            relay="wss://relay.youam.network",
            signing_key=sk,
        )
        assert card.payload_formats == ["text/plain", "text/markdown"]

    def test_custom_payload_formats(self, keypair):
        """Custom payload_formats are preserved."""
        sk, _ = keypair
        card = create_contact_card(
            address="alice::youam.network",
            display_name="Alice",
            relay="wss://relay.youam.network",
            signing_key=sk,
            payload_formats=["text/plain", "application/json"],
        )
        assert card.payload_formats == ["text/plain", "application/json"]

    def test_payload_formats_in_dict(self, keypair):
        """payload_formats appears in the serialized dict."""
        sk, _ = keypair
        card = create_contact_card(
            address="alice::youam.network",
            display_name="Alice",
            relay="wss://relay.youam.network",
            signing_key=sk,
        )
        d = contact_card_to_dict(card)
        assert d["payload_formats"] == ["text/plain", "text/markdown"]

    def test_payload_formats_roundtrip(self, keypair):
        """payload_formats survives serialize/deserialize."""
        sk, _ = keypair
        card = create_contact_card(
            address="alice::youam.network",
            display_name="Alice",
            relay="wss://relay.youam.network",
            signing_key=sk,
            payload_formats=["text/plain", "application/json"],
        )
        d = contact_card_to_dict(card)
        restored = contact_card_from_dict(d)
        assert restored.payload_formats == card.payload_formats

    def test_payload_formats_excluded_from_signature_scope(self, keypair):
        """payload_formats must NOT appear in the signable dict."""
        sk, _ = keypair
        card_default = create_contact_card(
            address="alice::youam.network",
            display_name="Alice",
            relay="wss://relay.youam.network",
            signing_key=sk,
        )
        card_custom = create_contact_card(
            address="alice::youam.network",
            display_name="Alice",
            relay="wss://relay.youam.network",
            signing_key=sk,
            payload_formats=["application/json"],
        )
        # Both must pass verification
        verify_contact_card(card_default)
        verify_contact_card(card_custom)

        # payload_formats must NOT be in the signable dict
        assert "payload_formats" not in _build_signable_dict(card_default)
        assert "payload_formats" not in _build_signable_dict(card_custom)

        # Signatures are identical because payload_formats is excluded
        assert card_default.signature == card_custom.signature


# ---------------------------------------------------------------------------
# Fingerprint (CARD-03)
# ---------------------------------------------------------------------------


class TestFingerprint:
    def test_fingerprint_auto_computed(self, keypair):
        """fingerprint is auto-computed as a 64-char hex string (SHA-256)."""
        sk, _ = keypair
        card = create_contact_card(
            address="alice::youam.network",
            display_name="Alice",
            relay="wss://relay.youam.network",
            signing_key=sk,
        )
        assert card.fingerprint is not None
        assert len(card.fingerprint) == 64
        # Must be valid hex
        int(card.fingerprint, 16)

    def test_fingerprint_matches_public_key(self, keypair):
        """fingerprint equals SHA-256 hex of the Ed25519 public key bytes."""
        sk, _ = keypair
        card = create_contact_card(
            address="alice::youam.network",
            display_name="Alice",
            relay="wss://relay.youam.network",
            signing_key=sk,
        )
        vk = deserialize_verify_key(card.public_key)
        expected = public_key_fingerprint(vk)
        assert card.fingerprint == expected

    def test_fingerprint_in_dict(self, keypair):
        """fingerprint appears in the serialized dict."""
        sk, _ = keypair
        card = create_contact_card(
            address="alice::youam.network",
            display_name="Alice",
            relay="wss://relay.youam.network",
            signing_key=sk,
        )
        d = contact_card_to_dict(card)
        assert d["fingerprint"] == card.fingerprint

    def test_fingerprint_roundtrip(self, keypair):
        """fingerprint survives serialize/deserialize."""
        sk, _ = keypair
        card = create_contact_card(
            address="alice::youam.network",
            display_name="Alice",
            relay="wss://relay.youam.network",
            signing_key=sk,
        )
        d = contact_card_to_dict(card)
        restored = contact_card_from_dict(d)
        assert restored.fingerprint == card.fingerprint

    def test_fingerprint_excluded_from_signature_scope(self, keypair):
        """fingerprint must NOT appear in the signable dict."""
        sk, _ = keypair
        card = create_contact_card(
            address="alice::youam.network",
            display_name="Alice",
            relay="wss://relay.youam.network",
            signing_key=sk,
        )
        assert "fingerprint" not in _build_signable_dict(card)

    def test_different_keys_different_fingerprints(self):
        """Two cards with different signing keys produce different fingerprints."""
        from nacl.signing import SigningKey

        sk1 = SigningKey.generate()
        sk2 = SigningKey.generate()
        card1 = create_contact_card(
            address="alice::youam.network",
            display_name="Alice",
            relay="wss://relay.youam.network",
            signing_key=sk1,
        )
        card2 = create_contact_card(
            address="bob::youam.network",
            display_name="Bob",
            relay="wss://relay.youam.network",
            signing_key=sk2,
        )
        assert card1.fingerprint != card2.fingerprint


# ---------------------------------------------------------------------------
# v1.1 Backward compatibility
# ---------------------------------------------------------------------------


class TestV11BackwardCompat:
    def test_v10_card_dict_deserializes_without_new_fields(self, keypair):
        """A v1.0 dict (no payload_formats, no fingerprint) deserializes
        with those fields as None."""
        sk, _ = keypair
        card = create_contact_card(
            address="alice::youam.network",
            display_name="Alice",
            relay="wss://relay.youam.network",
            signing_key=sk,
        )
        # Build a v1.0 dict by removing the new fields
        d = contact_card_to_dict(card)
        d.pop("payload_formats", None)
        d.pop("fingerprint", None)
        # Deserialize (signature is still valid because new fields aren't signed)
        restored = contact_card_from_dict(d)
        assert restored.payload_formats is None
        assert restored.fingerprint is None

    def test_v11_card_verified_by_v10_signable_dict(self, keypair):
        """A v1.0 agent using _build_signable_dict produces the same
        verification result for a v1.1 card."""
        sk, _ = keypair
        card = create_contact_card(
            address="alice::youam.network",
            display_name="Alice",
            relay="wss://relay.youam.network",
            signing_key=sk,
        )
        # Confirm card has v1.1 fields
        assert card.payload_formats is not None
        assert card.fingerprint is not None

        # Signable dict must NOT contain the new fields
        signable = _build_signable_dict(card)
        assert "payload_formats" not in signable
        assert "fingerprint" not in signable

        # v1.0 verification still works
        verify_contact_card(card)


# ---------------------------------------------------------------------------
# Multi-relay support (CARD-04)
# ---------------------------------------------------------------------------


class TestMultiRelay:
    """Tests for the relays field on ContactCard (CARD-04)."""

    def test_relays_default_none(self, keypair):
        """Cards created without relays= have relays=None."""
        sk, _ = keypair
        card = create_contact_card(
            address="alice::youam.network",
            display_name="Alice",
            relay="wss://relay.youam.network",
            signing_key=sk,
        )
        assert card.relays is None

    def test_relays_stored_on_card(self, keypair):
        """Cards created with relays= store the array."""
        sk, _ = keypair
        urls = ["wss://relay1.example.com/ws", "wss://relay2.example.com/ws"]
        card = create_contact_card(
            address="alice::youam.network",
            display_name="Alice",
            relay="wss://relay1.example.com/ws",
            signing_key=sk,
            relays=urls,
        )
        assert card.relays == urls

    def test_relays_serialization(self, keypair):
        """contact_card_to_dict includes relays when present."""
        sk, _ = keypair
        urls = ["wss://relay1.example.com/ws", "wss://relay2.example.com/ws"]
        card = create_contact_card(
            address="alice::youam.network",
            display_name="Alice",
            relay="wss://relay1.example.com/ws",
            signing_key=sk,
            relays=urls,
        )
        d = contact_card_to_dict(card)
        assert d["relays"] == urls

    def test_relays_omitted_when_none(self, keypair):
        """contact_card_to_dict omits relays when it is None."""
        sk, _ = keypair
        card = create_contact_card(
            address="alice::youam.network",
            display_name="Alice",
            relay="wss://relay.youam.network",
            signing_key=sk,
        )
        d = contact_card_to_dict(card)
        assert "relays" not in d

    def test_relays_deserialization(self, keypair):
        """contact_card_from_dict restores relays from dict."""
        sk, _ = keypair
        urls = ["wss://relay1.example.com/ws", "wss://relay2.example.com/ws"]
        card = create_contact_card(
            address="alice::youam.network",
            display_name="Alice",
            relay="wss://relay1.example.com/ws",
            signing_key=sk,
            relays=urls,
        )
        d = contact_card_to_dict(card)
        restored = contact_card_from_dict(d)
        assert restored.relays == urls

    def test_v10_dict_deserializes_without_relays(self, keypair):
        """A v1.0 dict (no relays key) deserializes with relays=None."""
        sk, _ = keypair
        card = create_contact_card(
            address="alice::youam.network",
            display_name="Alice",
            relay="wss://relay.youam.network",
            signing_key=sk,
        )
        d = contact_card_to_dict(card)
        assert "relays" not in d  # no relays key
        restored = contact_card_from_dict(d)
        assert restored.relays is None

    def test_relays_outside_signature_scope(self, keypair):
        """relays MUST NOT appear in _build_signable_dict."""
        sk, _ = keypair
        card = create_contact_card(
            address="alice::youam.network",
            display_name="Alice",
            relay="wss://relay.youam.network",
            signing_key=sk,
            relays=["wss://relay1.example.com/ws", "wss://relay2.example.com/ws"],
        )
        signable = _build_signable_dict(card)
        assert "relays" not in signable

    def test_relays_does_not_change_signature(self, keypair):
        """Card WITH relays has identical signature to same card WITHOUT relays."""
        sk, _ = keypair
        card_without = create_contact_card(
            address="alice::youam.network",
            display_name="Alice",
            relay="wss://relay.youam.network",
            signing_key=sk,
        )
        card_with = create_contact_card(
            address="alice::youam.network",
            display_name="Alice",
            relay="wss://relay.youam.network",
            signing_key=sk,
            relays=["wss://relay1.example.com/ws", "wss://relay2.example.com/ws"],
        )
        assert card_without.signature == card_with.signature

    def test_relays_card_verifies(self, keypair):
        """A card with relays passes signature verification."""
        sk, _ = keypair
        card = create_contact_card(
            address="alice::youam.network",
            display_name="Alice",
            relay="wss://relay.youam.network",
            signing_key=sk,
            relays=["wss://relay1.example.com/ws", "wss://relay2.example.com/ws"],
        )
        verify_contact_card(card)  # should not raise

    def test_relays_roundtrip(self, keypair):
        """Full roundtrip: create_contact_card -> to_dict -> from_dict -> verify -> relays present."""
        sk, _ = keypair
        urls = ["wss://relay1.example.com/ws", "wss://relay2.example.com/ws"]
        card = create_contact_card(
            address="alice::youam.network",
            display_name="Alice",
            relay="wss://relay1.example.com/ws",
            signing_key=sk,
            relays=urls,
        )
        d = contact_card_to_dict(card)
        restored = contact_card_from_dict(d)
        verify_contact_card(restored)
        assert restored.relays == urls
        assert restored == card

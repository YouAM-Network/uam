"""Tests for SDK-side webhook signature verification.

Covers verify_webhook_signature():
- Valid signature round-trip
- Invalid/wrong signature rejection
- Wrong key rejection
- Missing prefix rejection
- Empty signature rejection
- Cross-module round-trip with relay compute_webhook_signature()
"""

from __future__ import annotations

from uam.relay.webhook import compute_webhook_signature
from uam.sdk.webhook_verify import verify_webhook_signature


class TestVerifyWebhookSignature:
    """verify_webhook_signature() unit tests."""

    def test_valid_signature_returns_true(self):
        """Correctly computed signature verifies as True."""
        payload = b'{"from":"alice","to":"bob"}'
        token = "test-api-key-123"
        sig = compute_webhook_signature(payload, token)
        assert verify_webhook_signature(payload, sig, token) is True

    def test_invalid_signature_returns_false(self):
        """Wrong hex digest returns False."""
        payload = b'{"test":true}'
        token = "my-key"
        bad_sig = "sha256=0000000000000000000000000000000000000000000000000000000000000000"
        assert verify_webhook_signature(payload, bad_sig, token) is False

    def test_wrong_key_returns_false(self):
        """Signature computed with different key fails verification."""
        payload = b'{"test":true}'
        sig = compute_webhook_signature(payload, "correct-key")
        assert verify_webhook_signature(payload, sig, "wrong-key") is False

    def test_missing_prefix_returns_false(self):
        """Signature without 'sha256=' prefix is rejected."""
        payload = b'{"test":true}'
        token = "my-key"
        sig = compute_webhook_signature(payload, token)
        # Strip the prefix
        hex_only = sig[len("sha256="):]
        assert verify_webhook_signature(payload, hex_only, token) is False

    def test_empty_signature_returns_false(self):
        """Empty signature string is rejected."""
        payload = b'{"test":true}'
        assert verify_webhook_signature(payload, "", "my-key") is False

    def test_round_trip_with_relay_signer(self):
        """End-to-end: relay signs, SDK verifies -- must match."""
        payload = b'{"message_id":"abc","from":"alice::relay.test","to":"bob::relay.test"}'
        token = "agent-secret-key-456"

        # Relay side: compute signature
        sig = compute_webhook_signature(payload, token)

        # SDK side: verify signature
        assert verify_webhook_signature(payload, sig, token) is True

        # Tampered payload should fail
        tampered = payload + b"extra"
        assert verify_webhook_signature(tampered, sig, token) is False

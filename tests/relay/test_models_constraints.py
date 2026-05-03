"""Failing-by-design Pydantic constraint tests for relay/models.py (T6.2 Wave 0).

These tests RED at HEAD because relay/models.py exposes most fields as bare
``str``/``int``/``list[str]`` with no Field constraints. They GREEN after Plan
46-02 lands the catalogue from RESEARCH § Pydantic Constraint Catalogue.

Adversarial cases (RED at HEAD):
  - ``RegisterRequest.agent_name`` length / pattern
  - ``RegisterRequest.public_key`` length / pattern
  - ``RegisterRequest.webhook_url`` https-only / max_length
  - ``SendRequest.envelope`` 64 KiB cap
  - ``ReceiptRequest.type`` Literal whitelist
  - ``FederationDeliverRequest.via`` max items
  - ``FederationDeliverRequest.hop_count`` upper bound
  - ``SetReputationRequest.score`` 0-100 range
  - ``DemoSendRequest.message`` 2 KiB cap
  - ``ReserveClaimRequest.claim_token`` length / pattern

Sanity round-trips (GREEN at HEAD AND after 46-02):
  - Each happy-path construction; constraints must NOT reject legitimate input.

Note (Rule 3 deviation, RED-by-design plan adjustment):
  ``ReceiptRequest`` has fields ``type: str`` and ``timestamp: str | None`` ONLY
  (no ``message_id``). The plan stub passed ``message_id="m1"`` which would
  succeed today (extras ignored) but the same call would BREAK after extra='forbid'
  lands in 46-02. Tests below use only real fields so the test asserts the
  constraint, not an unrelated forbid-extras rule.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from uam.relay.models import (
    DemoSendRequest,
    FederationDeliverRequest,
    ReceiptRequest,
    RegisterRequest,
    ReserveClaimRequest,
    SendRequest,
    SetReputationRequest,
)

# A valid base64-encoded 32-byte Ed25519 verify key (44 chars padded).
VALID_PUBKEY = "AbcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNopq="


class TestAgentNameConstraint:
    def test_agent_name_too_long_422(self):
        with pytest.raises(ValidationError, match="(max_length|String should have at most)"):
            RegisterRequest(agent_name="A" * 1000, public_key=VALID_PUBKEY)

    def test_agent_name_invalid_chars_422(self):
        # Catalogue says agent_name pattern = ^[a-z0-9-]+$ (lowercase, digits, dash only)
        with pytest.raises(ValidationError, match="(pattern|String should match)"):
            RegisterRequest(agent_name="HAS_UNDERSCORES", public_key=VALID_PUBKEY)

    def test_agent_name_starts_with_dash_422(self):
        # Many catalogues forbid leading dash to avoid CLI flag confusion.
        with pytest.raises(ValidationError, match="(pattern|String should match)"):
            RegisterRequest(agent_name="-bob", public_key=VALID_PUBKEY)

    def test_agent_name_valid_passes(self):
        # Round-trip sanity — must NOT be rejected by 46-02.
        req = RegisterRequest(agent_name="bob-123", public_key=VALID_PUBKEY)
        assert req.agent_name == "bob-123"


class TestPublicKeyConstraint:
    def test_public_key_invalid_pattern_422(self):
        with pytest.raises(ValidationError, match="(pattern|String should match)"):
            RegisterRequest(agent_name="bob", public_key="!!!not-base64!!!")

    def test_public_key_too_long_422(self):
        with pytest.raises(ValidationError, match="(max_length|String should have at most)"):
            RegisterRequest(agent_name="bob", public_key="A" * 100)

    def test_public_key_valid_passes(self):
        req = RegisterRequest(agent_name="bob", public_key=VALID_PUBKEY)
        assert req.public_key == VALID_PUBKEY


class TestWebhookUrlConstraint:
    def test_webhook_url_must_be_https_422(self):
        with pytest.raises(ValidationError, match="(pattern|String should match|https)"):
            RegisterRequest(
                agent_name="bob",
                public_key=VALID_PUBKEY,
                webhook_url="http://example.com/hook",
            )

    def test_webhook_url_too_long_422(self):
        with pytest.raises(ValidationError, match="(max_length|String should have at most)"):
            RegisterRequest(
                agent_name="bob",
                public_key=VALID_PUBKEY,
                webhook_url="https://example.com/" + "x" * 3000,
            )

    def test_webhook_url_none_passes(self):
        req = RegisterRequest(agent_name="bob", public_key=VALID_PUBKEY, webhook_url=None)
        assert req.webhook_url is None

    def test_webhook_url_valid_https_passes(self):
        req = RegisterRequest(
            agent_name="bob",
            public_key=VALID_PUBKEY,
            webhook_url="https://example.com/hook",
        )
        assert req.webhook_url == "https://example.com/hook"


class TestEnvelopeSizeConstraint:
    def test_envelope_too_large_422(self):
        # Serialized JSON > 65536 bytes must be rejected.
        big_payload = {"k": "x" * 70000}
        with pytest.raises(ValidationError, match="(envelope|size|65536|max|too large)"):
            SendRequest(envelope=big_payload)

    def test_envelope_normal_size_passes(self):
        SendRequest(envelope={"from": "a::b", "to": "c::d", "ciphertext": "ok"})


class TestReceiptTypeConstraint:
    def test_receipt_type_arbitrary_string_422(self):
        # Catalogue: type must be Literal["receipt.read", "receipt.delivered", "receipt.failed"].
        with pytest.raises(ValidationError, match="(literal|expected|input|Literal)"):
            ReceiptRequest(type="receipt.evil")

    def test_receipt_type_valid_passes(self):
        ReceiptRequest(type="receipt.read")


class TestFederationDeliverConstraints:
    def _base(self, **overrides):
        kwargs = dict(
            envelope={},
            via=[],
            hop_count=0,
            timestamp="2026-05-01T00:00:00Z",
            from_relay="a.example.com",
            nonce="x" * 22,
        )
        kwargs.update(overrides)
        return kwargs

    def test_via_list_too_long_422(self):
        with pytest.raises(ValidationError, match="(max_length|too long|at most)"):
            FederationDeliverRequest(**self._base(via=["x"] * 100))

    def test_hop_count_too_high_422(self):
        with pytest.raises(ValidationError, match="(le|less|at most)"):
            FederationDeliverRequest(**self._base(hop_count=999))

    def test_federation_happy_path_passes(self):
        # Round-trip sanity — must NOT be rejected by 46-02.
        FederationDeliverRequest(**self._base())


class TestReputationScoreConstraint:
    def test_score_above_100_422(self):
        with pytest.raises(ValidationError, match="(le|less|at most)"):
            SetReputationRequest(score=200)

    def test_score_negative_422(self):
        with pytest.raises(ValidationError, match="(ge|greater|at least)"):
            SetReputationRequest(score=-1)

    def test_score_in_range_passes(self):
        assert SetReputationRequest(score=50).score == 50
        assert SetReputationRequest(score=0).score == 0
        assert SetReputationRequest(score=100).score == 100


class TestDemoMessageConstraint:
    def test_demo_message_too_long_422(self):
        with pytest.raises(ValidationError, match="(max_length|String should have at most)"):
            DemoSendRequest(
                session_id="s" * 32,
                to_address="hello::a.example.com",
                message="x" * 5000,
            )

    def test_demo_message_within_cap_passes(self):
        DemoSendRequest(
            session_id="s" * 32,
            to_address="hello::a.example.com",
            message="hello",
        )


class TestReserveClaimConstraint:
    def test_claim_token_invalid_pattern_422(self):
        with pytest.raises(ValidationError, match="(pattern|String should match)"):
            ReserveClaimRequest(claim_token="!!!", public_key=VALID_PUBKEY)

    def test_claim_token_too_long_422(self):
        with pytest.raises(ValidationError, match="(max_length|String should have at most)"):
            ReserveClaimRequest(claim_token="x" * 200, public_key=VALID_PUBKEY)

    def test_claim_token_valid_passes(self):
        ReserveClaimRequest(claim_token="abc123def456", public_key=VALID_PUBKEY)

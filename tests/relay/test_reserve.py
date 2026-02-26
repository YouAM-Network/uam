"""Tests for reservation API routes (Phase 39).

Covers the full reservation lifecycle:
- Check availability (GET /reserve/check/{name})
- Create reservation (POST /reserve)
- Claim reservation (POST /reserve/claim)
- Reservation vCard download (GET /reserve/{token}/vcf)
- Identity vCard download (GET /agents/{address}/card.vcf)
- Identity card image (GET /agents/{address}/card.png)
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from uam.protocol import generate_keypair, serialize_verify_key

# Minimal JPEG stub: magic bytes + padding (avoids Pillow/DiceBear in tests)
JPEG_STUB = b"\xff\xd8\xff\xe0" + b"\x00" * 100


# ---------------------------------------------------------------------------
# Check availability
# ---------------------------------------------------------------------------


class TestCheckAvailability:
    """GET /api/v1/reserve/check/{name} -- address availability."""

    def test_check_available_address(self, client):
        """Available name returns 200 with available=True."""
        resp = client.get("/api/v1/reserve/check/newname")
        assert resp.status_code == 200
        data = resp.json()
        assert data["available"] is True
        assert data["address"] == "newname::test.local"

    def test_check_registered_address_unavailable(self, client, registered_agent):
        """Already-registered address returns available=False."""
        resp = client.get("/api/v1/reserve/check/testbot")
        assert resp.status_code == 200
        data = resp.json()
        assert data["available"] is False

    def test_check_reserved_address_unavailable(self, client):
        """Address with active reservation returns available=False."""
        # Create a reservation first
        client.post("/api/v1/reserve", json={"name": "taken"})
        resp = client.get("/api/v1/reserve/check/taken")
        assert resp.status_code == 200
        data = resp.json()
        assert data["available"] is False

    def test_check_name_with_double_colon_returns_400(self, client):
        """Name containing '::' is invalid and returns 400."""
        resp = client.get("/api/v1/reserve/check/bad::name")
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Create reservation
# ---------------------------------------------------------------------------


class TestCreateReservation:
    """POST /api/v1/reserve -- reserve an address."""

    def test_reserve_address_success(self, client):
        """Valid reservation returns 201 with claim_token, address, and vcf_url."""
        resp = client.post("/api/v1/reserve", json={"name": "scout"})
        assert resp.status_code == 201
        data = resp.json()
        assert data["address"] == "scout::test.local"
        assert isinstance(data["claim_token"], str)
        assert len(data["claim_token"]) > 0
        assert "expires_at" in data
        assert data["claim_token"] in data["vcf_url"]

    def test_reserve_duplicate_address_conflict(self, client):
        """Reserving the same name twice returns 409."""
        client.post("/api/v1/reserve", json={"name": "scout"})
        resp = client.post("/api/v1/reserve", json={"name": "scout"})
        assert resp.status_code == 409

    def test_reserve_registered_address_conflict(self, client, registered_agent):
        """Reserving an already-registered name returns 409."""
        resp = client.post("/api/v1/reserve", json={"name": "testbot"})
        assert resp.status_code == 409

    def test_reserve_rate_limit(self, client):
        """6th reservation from same IP returns 429."""
        for i in range(5):
            resp = client.post("/api/v1/reserve", json={"name": f"reserve{i}"})
            assert resp.status_code == 201, f"Reservation {i} failed: {resp.text}"

        resp = client.post("/api/v1/reserve", json={"name": "reserve5"})
        assert resp.status_code == 429

    def test_reserve_name_normalized(self, client):
        """Name is stripped and lowercased."""
        resp = client.post("/api/v1/reserve", json={"name": " Scout "})
        assert resp.status_code == 201
        data = resp.json()
        assert data["address"] == "scout::test.local"


# ---------------------------------------------------------------------------
# Claim reservation
# ---------------------------------------------------------------------------


class TestClaimReservation:
    """POST /api/v1/reserve/claim -- claim a reserved address."""

    def test_claim_reservation_success(self, client):
        """Valid claim registers the agent and returns address + token."""
        # Reserve
        res = client.post("/api/v1/reserve", json={"name": "scout"})
        assert res.status_code == 201
        claim_token = res.json()["claim_token"]

        # Generate keypair for claiming
        _sk, vk = generate_keypair()
        pk_str = serialize_verify_key(vk)

        # Claim
        resp = client.post("/api/v1/reserve/claim", json={
            "claim_token": claim_token,
            "public_key": pk_str,
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["address"] == "scout::test.local"
        assert isinstance(data["token"], str)
        assert len(data["token"]) > 0
        assert "relay" in data
        assert data["relay"].startswith("ws")  # ws:// or wss://

    def test_claim_invalid_token(self, client):
        """Claim with random token returns 404."""
        _sk, vk = generate_keypair()
        pk_str = serialize_verify_key(vk)
        resp = client.post("/api/v1/reserve/claim", json={
            "claim_token": "nonexistent-token-value",
            "public_key": pk_str,
        })
        assert resp.status_code == 404

    def test_claim_already_claimed(self, client):
        """Claiming the same reservation twice returns 409."""
        # Reserve
        res = client.post("/api/v1/reserve", json={"name": "scout"})
        claim_token = res.json()["claim_token"]

        # First claim
        _sk1, vk1 = generate_keypair()
        pk1 = serialize_verify_key(vk1)
        resp1 = client.post("/api/v1/reserve/claim", json={
            "claim_token": claim_token,
            "public_key": pk1,
        })
        assert resp1.status_code == 200

        # Second claim with different keypair
        _sk2, vk2 = generate_keypair()
        pk2 = serialize_verify_key(vk2)
        resp2 = client.post("/api/v1/reserve/claim", json={
            "claim_token": claim_token,
            "public_key": pk2,
        })
        assert resp2.status_code == 409

    def test_claim_registers_agent(self, client):
        """After claiming, the agent is accessible via public-key endpoint."""
        # Reserve + claim
        res = client.post("/api/v1/reserve", json={"name": "scout"})
        claim_token = res.json()["claim_token"]

        _sk, vk = generate_keypair()
        pk_str = serialize_verify_key(vk)
        client.post("/api/v1/reserve/claim", json={
            "claim_token": claim_token,
            "public_key": pk_str,
        })

        # Verify agent is registered
        resp = client.get("/api/v1/agents/scout::test.local/public-key")
        assert resp.status_code == 200
        data = resp.json()
        assert data["public_key"] == pk_str

    def test_claim_with_invalid_public_key(self, client):
        """Claim with invalid public key returns 400."""
        res = client.post("/api/v1/reserve", json={"name": "scout"})
        claim_token = res.json()["claim_token"]

        resp = client.post("/api/v1/reserve/claim", json={
            "claim_token": claim_token,
            "public_key": "not-a-real-key",
        })
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Reservation vCard download
# ---------------------------------------------------------------------------


class TestReservationVcfDownload:
    """GET /api/v1/reserve/{token}/vcf -- reservation vCard file."""

    @patch("uam.cards.vcard.render_card")
    def test_download_reservation_vcf(self, mock_render, client):
        """Valid token returns vCard with correct MIME type and headers."""
        mock_render.return_value = JPEG_STUB

        # Reserve
        res = client.post("/api/v1/reserve", json={"name": "scout"})
        assert res.status_code == 201
        claim_token = res.json()["claim_token"]

        # Download vcf
        resp = client.get(f"/api/v1/reserve/{claim_token}/vcf")
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/vcard")
        assert "attachment" in resp.headers["content-disposition"]
        assert "reservation.scout.vcf" in resp.headers["content-disposition"]

        body = resp.text
        assert "BEGIN:VCARD" in body
        assert f"X-UAM-CLAIM-TOKEN:{claim_token}" in body

    def test_download_vcf_invalid_token(self, client):
        """Invalid claim token returns 404."""
        resp = client.get("/api/v1/reserve/badtoken/vcf")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Identity vCard download
# ---------------------------------------------------------------------------


class TestIdentityVcfDownload:
    """GET /api/v1/agents/{address}/card.vcf -- identity vCard file."""

    @patch("uam.cards.vcard.render_card")
    def test_download_identity_vcf(self, mock_render, client, registered_agent):
        """Registered agent returns identity vCard with correct headers."""
        mock_render.return_value = JPEG_STUB

        resp = client.get("/api/v1/agents/testbot::test.local/card.vcf")
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/vcard")
        assert "attachment" in resp.headers["content-disposition"]
        assert "testbot.vcf" in resp.headers["content-disposition"]

        body = resp.text
        assert "BEGIN:VCARD" in body
        assert "X-UAM-ADDRESS:testbot::test.local" in body

    def test_download_identity_vcf_not_found(self, client):
        """Non-existent agent returns 404."""
        resp = client.get("/api/v1/agents/nobody::test.local/card.vcf")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Identity card image
# ---------------------------------------------------------------------------


class TestCardImage:
    """GET /api/v1/agents/{address}/card.png -- identity card image."""

    @patch("uam.relay.routes.agents.render_card")
    def test_download_card_image(self, mock_render, client, registered_agent):
        """Registered agent returns JPEG with Cache-Control header."""
        mock_render.return_value = JPEG_STUB

        resp = client.get("/api/v1/agents/testbot::test.local/card.png")
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "image/jpeg"
        assert resp.headers["cache-control"] == "public, max-age=3600"

        # Verify JPEG magic bytes
        assert resp.content[:2] == b"\xff\xd8"

    def test_download_card_image_not_found(self, client):
        """Non-existent agent returns 404."""
        resp = client.get("/api/v1/agents/nobody::test.local/card.png")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Full lifecycle integration
# ---------------------------------------------------------------------------


class TestReservationLifecycle:
    """End-to-end reservation flow: check -> reserve -> vcf -> claim -> verify."""

    @patch("uam.cards.vcard.render_card")
    def test_full_lifecycle(self, mock_render, client):
        """Complete lifecycle from check to claim to agent verification."""
        mock_render.return_value = JPEG_STUB

        # 1. Check availability
        check = client.get("/api/v1/reserve/check/lifecycle")
        assert check.status_code == 200
        assert check.json()["available"] is True

        # 2. Reserve
        reserve = client.post("/api/v1/reserve", json={"name": "lifecycle"})
        assert reserve.status_code == 201
        claim_token = reserve.json()["claim_token"]

        # 3. Check no longer available
        check2 = client.get("/api/v1/reserve/check/lifecycle")
        assert check2.json()["available"] is False

        # 4. Download reservation vCard
        vcf = client.get(f"/api/v1/reserve/{claim_token}/vcf")
        assert vcf.status_code == 200
        assert "BEGIN:VCARD" in vcf.text
        assert claim_token in vcf.text

        # 5. Claim with keypair
        _sk, vk = generate_keypair()
        pk_str = serialize_verify_key(vk)
        claim = client.post("/api/v1/reserve/claim", json={
            "claim_token": claim_token,
            "public_key": pk_str,
        })
        assert claim.status_code == 200
        assert claim.json()["address"] == "lifecycle::test.local"

        # 6. Verify agent is registered
        pubkey = client.get("/api/v1/agents/lifecycle::test.local/public-key")
        assert pubkey.status_code == 200
        assert pubkey.json()["public_key"] == pk_str

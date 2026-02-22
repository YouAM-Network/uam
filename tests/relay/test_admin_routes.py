"""Tests for admin API endpoints (SPAM-05).

Covers:
- Authentication enforcement (401, 503)
- Blocklist CRUD (add, list, remove)
- Allowlist CRUD (add, list, remove)
- Reputation inspection and admin override
- Input validation (pattern format, score range)
"""

from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

from uam.relay.app import create_app

ADMIN_KEY = "test-admin-key-secret"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def admin_app(tmp_path):
    """Create a relay app with UAM_ADMIN_API_KEY configured."""
    os.environ["UAM_DB_PATH"] = str(tmp_path / "admin_test.db")
    os.environ["UAM_RELAY_DOMAIN"] = "test.local"
    os.environ["UAM_ADMIN_API_KEY"] = ADMIN_KEY
    yield create_app()
    os.environ.pop("UAM_DB_PATH", None)
    os.environ.pop("UAM_RELAY_DOMAIN", None)
    os.environ.pop("UAM_ADMIN_API_KEY", None)


@pytest.fixture()
def admin_client(admin_app):
    """Return a TestClient with admin API key configured."""
    with TestClient(admin_app) as c:
        yield c


@pytest.fixture()
def no_key_app(tmp_path):
    """Create a relay app WITHOUT UAM_ADMIN_API_KEY."""
    os.environ["UAM_DB_PATH"] = str(tmp_path / "nokey_test.db")
    os.environ["UAM_RELAY_DOMAIN"] = "test.local"
    os.environ.pop("UAM_ADMIN_API_KEY", None)
    yield create_app()
    os.environ.pop("UAM_DB_PATH", None)
    os.environ.pop("UAM_RELAY_DOMAIN", None)


@pytest.fixture()
def no_key_client(no_key_app):
    """Return a TestClient with no admin key configured."""
    with TestClient(no_key_app) as c:
        yield c


def _headers() -> dict:
    """Return valid admin auth headers."""
    return {"X-Admin-Key": ADMIN_KEY}


# ---------------------------------------------------------------------------
# Auth enforcement
# ---------------------------------------------------------------------------


class TestAdminAuth:
    """Tests for admin API key authentication."""

    def test_blocklist_add_no_auth(self, admin_client):
        """POST without X-Admin-Key returns 401."""
        resp = admin_client.post(
            "/api/v1/admin/blocklist",
            json={"pattern": "spam::evil.com"},
        )
        assert resp.status_code == 401

    def test_blocklist_add_wrong_key(self, admin_client):
        """POST with wrong key returns 401."""
        resp = admin_client.post(
            "/api/v1/admin/blocklist",
            json={"pattern": "spam::evil.com"},
            headers={"X-Admin-Key": "wrong-key"},
        )
        assert resp.status_code == 401

    def test_blocklist_add_no_key_configured(self, no_key_client):
        """POST when UAM_ADMIN_API_KEY not set returns 503."""
        resp = no_key_client.post(
            "/api/v1/admin/blocklist",
            json={"pattern": "spam::evil.com"},
            headers={"X-Admin-Key": "any-key"},
        )
        assert resp.status_code == 503


# ---------------------------------------------------------------------------
# Blocklist CRUD
# ---------------------------------------------------------------------------


class TestBlocklistCRUD:
    """Tests for blocklist add/list/remove endpoints."""

    def test_blocklist_add(self, admin_client):
        """POST /admin/blocklist with valid key adds pattern, returns 201."""
        resp = admin_client.post(
            "/api/v1/admin/blocklist",
            json={"pattern": "spammer::evil.com", "reason": "spam"},
            headers=_headers(),
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["pattern"] == "spammer::evil.com"
        assert data["status"] == "added"

    def test_blocklist_list(self, admin_client):
        """GET /admin/blocklist returns all entries."""
        # Add two patterns first
        admin_client.post(
            "/api/v1/admin/blocklist",
            json={"pattern": "a::one.com"},
            headers=_headers(),
        )
        admin_client.post(
            "/api/v1/admin/blocklist",
            json={"pattern": "*::two.com"},
            headers=_headers(),
        )

        resp = admin_client.get("/api/v1/admin/blocklist", headers=_headers())
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 2
        patterns = [e["pattern"] for e in data["entries"]]
        assert "a::one.com" in patterns
        assert "*::two.com" in patterns

    def test_blocklist_remove(self, admin_client):
        """DELETE /admin/blocklist/{pattern} removes entry, returns 200."""
        # Add then remove
        admin_client.post(
            "/api/v1/admin/blocklist",
            json={"pattern": "remove_me::test.com"},
            headers=_headers(),
        )
        resp = admin_client.delete(
            "/api/v1/admin/blocklist/remove_me::test.com",
            headers=_headers(),
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "removed"

    def test_blocklist_remove_not_found(self, admin_client):
        """DELETE for non-existent pattern returns 404."""
        resp = admin_client.delete(
            "/api/v1/admin/blocklist/ghost::nowhere.com",
            headers=_headers(),
        )
        assert resp.status_code == 404

    def test_blocklist_invalid_pattern(self, admin_client):
        """POST with pattern missing '::' returns 400."""
        resp = admin_client.post(
            "/api/v1/admin/blocklist",
            json={"pattern": "no-separator"},
            headers=_headers(),
        )
        assert resp.status_code == 400
        assert "::" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# Allowlist CRUD
# ---------------------------------------------------------------------------


class TestAllowlistCRUD:
    """Tests for allowlist add/list/remove endpoints."""

    def test_allowlist_add(self, admin_client):
        """POST /admin/allowlist adds pattern."""
        resp = admin_client.post(
            "/api/v1/admin/allowlist",
            json={"pattern": "vip::trusted.org"},
            headers=_headers(),
        )
        assert resp.status_code == 201
        assert resp.json()["pattern"] == "vip::trusted.org"

    def test_allowlist_list(self, admin_client):
        """GET /admin/allowlist returns all entries."""
        admin_client.post(
            "/api/v1/admin/allowlist",
            json={"pattern": "x::good.com"},
            headers=_headers(),
        )
        resp = admin_client.get("/api/v1/admin/allowlist", headers=_headers())
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] >= 1

    def test_allowlist_remove(self, admin_client):
        """DELETE removes entry."""
        admin_client.post(
            "/api/v1/admin/allowlist",
            json={"pattern": "temp::allow.net"},
            headers=_headers(),
        )
        resp = admin_client.delete(
            "/api/v1/admin/allowlist/temp::allow.net",
            headers=_headers(),
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "removed"

    def test_allowlist_remove_not_found(self, admin_client):
        """DELETE for non-existent pattern returns 404."""
        resp = admin_client.delete(
            "/api/v1/admin/allowlist/ghost::nowhere.com",
            headers=_headers(),
        )
        assert resp.status_code == 404

    def test_allowlist_invalid_pattern(self, admin_client):
        """POST with pattern missing '::' returns 400."""
        resp = admin_client.post(
            "/api/v1/admin/allowlist",
            json={"pattern": "noseparator"},
            headers=_headers(),
        )
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Reputation endpoints
# ---------------------------------------------------------------------------


class TestReputationAdmin:
    """Tests for reputation inspection and admin override."""

    def _register_agent(self, client) -> dict:
        """Register an agent and return {address, token}."""
        from uam.protocol import generate_keypair, serialize_verify_key
        sk, vk = generate_keypair()
        pk_str = serialize_verify_key(vk)
        resp = client.post("/api/v1/register", json={
            "agent_name": "reptest",
            "public_key": pk_str,
        })
        assert resp.status_code == 200
        data = resp.json()
        return {"address": data["address"], "token": data["token"]}

    def test_reputation_get(self, admin_client):
        """GET /admin/reputation/{address} returns score and tier."""
        agent = self._register_agent(admin_client)
        resp = admin_client.get(
            f"/api/v1/admin/reputation/{agent['address']}",
            headers=_headers(),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["address"] == agent["address"]
        assert data["score"] == 30  # default
        assert data["tier"] == "throttled"  # 30 is throttled tier
        assert "messages_sent" in data
        assert "messages_rejected" in data

    def test_reputation_get_not_found(self, admin_client):
        """GET for unknown address returns 404."""
        resp = admin_client.get(
            "/api/v1/admin/reputation/ghost::unknown.com",
            headers=_headers(),
        )
        assert resp.status_code == 404

    def test_reputation_set(self, admin_client):
        """PUT /admin/reputation/{address} with score updates it."""
        agent = self._register_agent(admin_client)
        resp = admin_client.put(
            f"/api/v1/admin/reputation/{agent['address']}",
            json={"score": 85},
            headers=_headers(),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["score"] == 85
        assert data["tier"] == "full"

    def test_reputation_set_invalid_range_over(self, admin_client):
        """PUT with score >100 returns 400."""
        agent = self._register_agent(admin_client)
        resp = admin_client.put(
            f"/api/v1/admin/reputation/{agent['address']}",
            json={"score": 150},
            headers=_headers(),
        )
        assert resp.status_code == 400

    def test_reputation_set_invalid_range_under(self, admin_client):
        """PUT with score <0 returns 400."""
        agent = self._register_agent(admin_client)
        resp = admin_client.put(
            f"/api/v1/admin/reputation/{agent['address']}",
            json={"score": -10},
            headers=_headers(),
        )
        assert resp.status_code == 400

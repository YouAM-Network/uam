"""Tests for POST /api/v1/federation/deliver endpoint (FED-01).

Covers:
- Federation disabled returns 501
- Missing request body returns 422
- No auth required (federation uses relay-level signature, not bearer token)
"""

from __future__ import annotations

import os
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from uam.relay.app import create_app


@pytest.fixture()
def fed_app(tmp_path):
    """Create a relay app with federation disabled (default)."""
    import uam.db.engine as _eng
    import uam.db.session as _sess
    _eng._engine = None
    _sess._session_factory = None

    db_path = str(tmp_path / "fed_test.db")
    os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{db_path}"
    os.environ["UAM_DB_PATH"] = db_path
    os.environ["UAM_RELAY_DOMAIN"] = "test.local"
    os.environ["UAM_FEDERATION_ENABLED"] = "false"
    yield create_app()
    os.environ.pop("DATABASE_URL", None)
    os.environ.pop("UAM_DB_PATH", None)
    os.environ.pop("UAM_RELAY_DOMAIN", None)
    os.environ.pop("UAM_FEDERATION_ENABLED", None)
    _eng._engine = None
    _sess._session_factory = None


@pytest.fixture()
def fed_client(fed_app):
    """Return a TestClient for the federation-disabled app."""
    with TestClient(fed_app) as c:
        yield c


def _valid_federation_body() -> dict:
    """Return a minimal valid FederationDeliverRequest body."""
    return {
        "envelope": {"message_id": "test-fed-msg", "from": "a::other.relay", "to": "b::test.local"},
        "from_relay": "other.relay",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


class TestFederationDeliver:
    """Federation deliver endpoint tests."""

    def test_federation_disabled_returns_501(self, fed_client):
        """POST /federation/deliver with federation disabled returns 501."""
        resp = fed_client.post(
            "/api/v1/federation/deliver",
            json=_valid_federation_body(),
        )
        assert resp.status_code == 501
        data = resp.json()
        assert "not enabled" in data["detail"].lower() or "not implemented" in data["detail"].lower()

    def test_federation_missing_body_returns_422(self, fed_client):
        """POST without request body returns 422."""
        resp = fed_client.post("/api/v1/federation/deliver")
        assert resp.status_code == 422

    def test_federation_no_auth_required(self, fed_client):
        """POST without auth token returns 501 (not 401/403) -- no bearer auth needed."""
        resp = fed_client.post(
            "/api/v1/federation/deliver",
            json=_valid_federation_body(),
        )
        # Federation disabled returns 501, NOT an auth error
        assert resp.status_code != 401
        assert resp.status_code != 403
        assert resp.status_code == 501

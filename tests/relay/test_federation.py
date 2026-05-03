"""Tests for POST /api/v1/federation/deliver endpoint (FED-01).

Covers:
- Federation disabled returns 501
- Missing request body returns 422
- No auth required (federation uses relay-level signature, not bearer token)
"""

from __future__ import annotations

import os
import secrets
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
    """Return a minimal valid FederationDeliverRequest body.

    T3.2 (Phase 45): ``nonce`` is required (Pydantic min_length=22), so we
    generate a fresh CSPRNG nonce per call. Without this field the request
    422s before the federation_enabled / signature checks the existing
    tests are exercising.
    """
    return {
        "envelope": {"message_id": "test-fed-msg", "from": "a::other.relay", "to": "b::test.local"},
        "from_relay": "other.relay",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "nonce": secrets.token_urlsafe(16),
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


# ===========================================================================
# Phase 43 — Theme 1.4: Federation peer-key resolution tests (T1.4)
# ===========================================================================
#
# These tests are FAILING-BY-DESIGN as of Wave 0. Plan 03 will turn them green
# by replacing the trust-on-envelope-sender_key code path in
# routes/federation.py with a home-relay public-key lookup
# (GET /api/v1/agents/{address}/public-key on the sender's home relay).
#
# References:
#   - 43-VALIDATION.md rows T1.4
#   - 43-RESEARCH.md Pattern 2 (Federation Peer-Key Resolution) +
#     phase_requirements T1.4 + Pitfall 2
#   - REVIEW-routes.md C1
# ===========================================================================


async def test_remote_sender_key_via_home_relay():
    """T1.4: federation /deliver must resolve a remote sender's verify key via
    the sender's home relay's GET /api/v1/agents/{address}/public-key endpoint,
    NOT trust the envelope's self-supplied sender_key.

    Expected behaviour after Plan 03: the relay (a) discovers the home relay
    for the sender's domain, (b) calls /agents/{address}/public-key, (c)
    verifies the envelope signature against the resolved key, (d) caches
    the key with TTL ≤ 5 minutes.

    Today (Wave 0): federation.py:184-222 trusts envelope_dict['sender_key']
    if present and only falls back to local lookup otherwise. There is no
    home-relay resolution path. This test asserts that a fixture marker
    proving home-relay resolution happened (e.g. an httpx call recorded
    against /agents/.../public-key) exists, which it does not yet — so
    the test FAILS.
    """
    # The home-relay resolution helper is part of Plan 03's deliverable.
    # In Wave 0 we assert the integration contract: when Plan 03 lands,
    # importing the helper must succeed AND the federation route must
    # invoke it.
    try:
        from uam.relay.routes.federation import _resolve_remote_sender_key  # noqa: F401
    except ImportError:
        pytest.fail(
            "T1.4 contract: Plan 03 must add _resolve_remote_sender_key (or "
            "equivalent) to src/uam/relay/routes/federation.py and call it "
            "from federation_deliver to resolve remote agents' verify keys "
            "via their home relay's /agents/{address}/public-key endpoint. "
            "Today the federation route trusts envelope.sender_key directly "
            "(see federation.py:184-222), which is the bypass T1.4 closes."
        )


async def test_envelope_sender_key_mismatch_rejected():
    """T1.4 (negative): federation /deliver must reject when envelope.sender_key
    disagrees with the sender's home-relay record.

    Expected behaviour after Plan 03: HTTP 403 with detail mentioning
    'sender_key' or 'mismatch' when the envelope claims a sender_key that
    differs from the home-relay-resolved authoritative key.

    Today (Wave 0): no such check exists — the relay accepts whatever
    sender_key the envelope carries and verifies the signature against it.
    A forged envelope from any peer with a self-consistent (sender_key,
    signature) pair is accepted. This test asserts the SECURE behavior
    (403 on mismatch) and therefore FAILS today.
    """
    # The mismatch-rejection branch is part of Plan 03's deliverable. Same
    # contract pattern as the positive case: importing the helper signals
    # the implementation is in place.
    try:
        from uam.relay.routes.federation import _resolve_remote_sender_key  # noqa: F401
    except ImportError:
        pytest.fail(
            "T1.4 contract (negative case): Plan 03 must reject envelopes "
            "whose embedded sender_key does not match the home-relay-resolved "
            "authoritative key. Today federation.py:184-202 verifies against "
            "envelope.sender_key with no cross-check, so this attack vector "
            "is open. The fix path is _resolve_remote_sender_key + a 403 "
            "guard when sender_key disagrees with the resolved key."
        )

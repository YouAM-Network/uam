"""Q1 — FastAPI exception handler maps UAMError subclasses to status codes.

Phase 48 Wave 0 — failing until 48-01 wires ``register_uam_handler()`` into
``create_app()``. Until then the test endpoints raise the new
ValidationError / IncompatibleVersionError / ContactCardExpired classes,
which (a) don't exist yet (ImportError) and (b) when they do exist, would
bubble up as 500s without the central handler. Both states are RED.
"""

from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(tmp_path):
    """Build a relay app with a temp DB + 4 test endpoints that each raise
    one of the typed errors covered by Wave 1.

    The handler is registered by Wave 1 inside ``create_app()`` itself; here
    we only need a route that raises so the handler can be exercised.
    """
    os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{tmp_path / 'eh.db'}"
    os.environ["UAM_DB_PATH"] = str(tmp_path / "eh.db")
    os.environ["UAM_RELAY_DOMAIN"] = "test.local"

    import uam.db.engine as _eng
    import uam.db.session as _sess
    _eng._engine = None
    _sess._session_factory = None

    from uam.relay.app import create_app
    app = create_app()

    # Imports inside the fixture so missing-symbol failures show up at
    # FIXTURE-resolution time (still RED, just localized).
    from fastapi import APIRouter
    from uam.protocol.errors import (  # NEW in Wave 1
        ValidationError,
        IncompatibleVersionError,
        ContactCardExpired,
        SignatureVerificationError,
    )

    router = APIRouter()

    @router.get("/_test/raise/validation")
    async def _r_validation():
        raise ValidationError("bad input")

    @router.get("/_test/raise/version")
    async def _r_version():
        raise IncompatibleVersionError("99.0", ("0",))

    @router.get("/_test/raise/expired")
    async def _r_expired():
        raise ContactCardExpired("alice::test", "2020-01-01T00:00:00Z")

    @router.get("/_test/raise/signature")
    async def _r_sig():
        raise SignatureVerificationError("bad sig")

    app.include_router(router)
    with TestClient(app) as c:
        yield c

    for k in ("DATABASE_URL", "UAM_DB_PATH", "UAM_RELAY_DOMAIN"):
        os.environ.pop(k, None)
    _eng._engine = None
    _sess._session_factory = None


def test_validation_returns_400_with_envelope(client):
    r = client.get("/_test/raise/validation")
    assert r.status_code == 400
    body = r.json()
    assert body["error"] == "validation_error"
    assert "detail" in body
    assert "request_id" in body


def test_incompatible_version_returns_400(client):
    r = client.get("/_test/raise/version")
    assert r.status_code == 400
    assert r.json()["error"] == "incompatible_version"


def test_contact_card_expired_returns_400(client):
    r = client.get("/_test/raise/expired")
    assert r.status_code == 400
    assert r.json()["error"] == "contact_card_expired"


def test_signature_invalid_returns_401(client):
    r = client.get("/_test/raise/signature")
    assert r.status_code == 401
    assert r.json()["error"] == "signature_invalid"


def test_response_includes_request_id(client):
    r = client.get("/_test/raise/validation")
    assert r.json().get("request_id") is not None

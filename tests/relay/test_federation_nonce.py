"""T3.2 — federation route-level nonce dedup failing-by-design tests (Wave 0).

Tests will RED until Plan 45-02 wires ``record_nonce`` into the federation
``deliver`` route, and adds ``nonce`` to ``FederationDeliverRequest`` and
``sign_federation_request``.

Per RESEARCH § Pattern 2 the contract is:

  - outbound: ``FederationService.forward`` includes a 22-char base64 nonce
    in the signed body
  - inbound: ``POST /api/v1/federation/deliver`` rejects bodies without
    ``nonce`` (Pydantic 422) and rejects the second delivery of any
    ``(from_relay, nonce)`` pair with HTTP 409
  - per-relay scope: relay-A nonce 'X' does NOT block relay-B nonce 'X'

The full signed-body construction is non-trivial (TestClient + fresh keys
+ canonical signature + peer relay setup), so the route-level integration
tests xfail today and will be implemented by Plan 45-02 alongside the
production code.  The CONTRACT is documented here so the implementer
inherits the test stubs.
"""

from __future__ import annotations

import json

import pytest


# ---------------------------------------------------------------------------
# Outbound — forward() must include a nonce
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_outbound_includes_nonce(monkeypatch):
    """``FederationService.forward`` must include a 22-char ``nonce`` in the
    signed body it POSTs to the peer relay.

    Plan 45-02 contract: ``sign_federation_request`` (or ``forward`` itself)
    generates a fresh ``nonce`` per outbound call, includes it in the body
    that gets canonicalized + signed, and the peer extracts it from the
    body for the dedup check.

    Today this test xfails because:
      (a) ``FederationService.forward`` does not currently generate or include
          a ``nonce`` field in the body;
      (b) constructing a real outbound call requires a Settings instance, a
          keypair, and a known_relay row — too much wiring for a Wave-0 stub.

    Plan 45-02 will replace this xfail with a concrete integration test that
    captures the body via ``httpx.AsyncClient.post`` monkeypatch and asserts
    on the captured ``nonce`` field.
    """
    pytest.xfail(
        "contract: FederationService.forward must include 'nonce' in body — "
        "Plan 45-02 implements + provides full integration test"
    )


# ---------------------------------------------------------------------------
# Inbound — missing nonce → 422
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_missing_nonce_rejected(client, registered_agent):
    """POST /api/v1/federation/deliver with a body missing ``nonce`` → 4xx.

    Plan 45-02 contract: ``FederationDeliverRequest`` adds
    ``nonce: str = Field(min_length=22, max_length=22)`` so Pydantic itself
    rejects bodies without the field with HTTP 422.  We accept either 400 or
    422 here — both are correct rejections.

    Today: the field is optional/absent and the request is processed (or
    rejected later for unrelated reasons like signature mismatch).  This
    test asserts the SECURE behavior — a missing nonce alone must reject.
    """
    body = {
        "envelope": {"placeholder": "would-be-rejected-elsewhere-too"},
        "via": ["relay-source"],
        "hop_count": 1,
        "timestamp": "2026-05-02T00:00:00Z",
        "from_relay": "relay-source.test",
        # NO nonce field
    }
    resp = client.post("/api/v1/federation/deliver", json=body)
    # Either 400 (missing nonce — Pydantic) or 422 (validation) is acceptable.
    # MUST NOT be 200/204/202.
    assert resp.status_code in (400, 422), (
        f"missing nonce should reject; got {resp.status_code}: {resp.text[:200]}"
    )
    # Sanity-check: the rejection mentions 'nonce' somewhere.
    assert "nonce" in resp.text.lower(), (
        f"rejection should mention the missing 'nonce' field; got: {resp.text[:200]}"
    )


# ---------------------------------------------------------------------------
# Inbound — replay → 409
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_replay_rejected(client, registered_agent):
    """POSTing the same federation body twice → 2nd returns 409 (nonce replay).

    Plan 45-02 contract: after Step 6 destination check and BEFORE Step 7
    signature verify, the route consults ``record_nonce(from_relay, nonce)``.
    First call returns True (proceed); second call returns False (reject 409).

    Today: ``federation_deliver`` has no nonce dedup at all — the same body
    POSTed twice produces two deliveries.  The integration helper to build
    a real signed federation body is non-trivial, so this test is xfail; Plan
    45-02 must implement both the production fix AND the test scaffolding.
    """
    pytest.xfail(
        "contract: 2nd delivery of same (from_relay, nonce) returns 409 — "
        "Plan 45-02 implements + provides signed-body integration helper"
    )


@pytest.mark.asyncio
async def test_nonce_scoped_per_relay(client, registered_agent):
    """Same nonce used by two different from_relay values → both succeed.

    Plan 45-02 contract: per-relay scope means the dedup key is
    ``(from_relay, nonce)``, not ``nonce`` alone.

    Today: no dedup exists.  This test xfails alongside ``test_replay_rejected``
    pending the integration helper.
    """
    pytest.xfail(
        "contract: per-relay nonce scope ((from_relay, nonce) is the dedup key) — "
        "Plan 45-02 implements + provides signed-body integration helper"
    )

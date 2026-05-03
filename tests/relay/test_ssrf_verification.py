"""T5.2 — verification HTTPS-fallback redirect refusal (Wave 0, failing-by-design).

Tests will RED until Plan 45-04 changes ``follow_redirects=True`` →
``follow_redirects=False`` in ``src/uam/relay/verification.py:172``.

Per RESEARCH § Pattern 3, the .well-known fallback in
``verify_domain_ownership`` currently has ``follow_redirects=True`` — an
attacker who controls ``example.com/.well-known/uam.json`` can 302 the
verifier to ``https://attacker.example/uam.json`` and have the relay fetch
attacker-controlled content while believing it spoke to ``example.com``.

The fix is two-line: drop ``follow_redirects=True`` and add explicit
``follow_redirects=False`` so the contract is clear at the callsite.
"""

from __future__ import annotations

import inspect

import pytest


# ---------------------------------------------------------------------------
# Source-introspection: the keyword must be False, not True
# ---------------------------------------------------------------------------


def test_no_redirect_following():
    """``verify_domain_ownership`` constructs ``httpx.AsyncClient`` with
    ``follow_redirects=False``.

    AFTER Plan 45-04 lands the fix, ``follow_redirects=True`` MUST NOT appear
    in the function source, and ``follow_redirects=False`` MUST appear (so
    the contract is explicit at the callsite, not relying on httpx defaults
    drifting).
    """
    from uam.relay import verification

    src = inspect.getsource(verification.verify_domain_ownership)
    assert "follow_redirects=True" not in src, (
        "verify_domain_ownership still uses follow_redirects=True — "
        "T5.2 not closed"
    )
    assert "follow_redirects=False" in src, (
        "verify_domain_ownership must explicitly set follow_redirects=False "
        "(don't rely on httpx defaults)"
    )


# ---------------------------------------------------------------------------
# Behavioral check: a 302 on the HTTPS fallback fails verification
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_redirect_refused():
    """``verify_domain_ownership`` rejects a 302 redirect on the HTTPS fallback path.

    Even if the redirect target is itself a public host, the function must
    return failure — the .well-known/uam.json contract is "no redirects".

    Plan 45-04 contract: when the HTTPS fallback receives a 3xx response,
    ``verify_domain_ownership`` returns ``(False, "https", "...")`` — it does
    NOT chase the Location header.

    Wave-0 stub: the existing function has multiple test seams (DNS resolver,
    httpx mock, public-IP guard) and Plan 45-04's executor is best placed to
    write a thorough integration test once the fix lands.  The contract is
    pinned via ``test_no_redirect_following`` (source introspection).
    """
    pytest.xfail(
        "Plan 45-04 implements redirect-refusal; the source-introspection test "
        "above pins the contract — full integration test ships with the fix."
    )

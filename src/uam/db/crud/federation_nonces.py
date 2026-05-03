"""CRUD operations for FederationNonce (relay-to-relay nonce dedup).

Phase 45 T3.2 — defeats federation request replay.

Mirrors :mod:`uam.db.crud.dedup` for ``seen_message_ids``. The composite
``(from_relay, nonce)`` PK on the ``federation_nonces`` table guarantees an
atomic INSERT-or-conflict; an ``IntegrityError`` on conflict means this
exact ``(from_relay, nonce)`` was already seen — caller treats as replay.

Per-relay scope is intentional: relay-A using a 22-char random nonce does
NOT block relay-B from also using the same string. The dedup key is the
COMPOSITE pair, not the nonce alone.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import delete as sa_delete
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from uam.db.models import FederationNonce


async def record_nonce(
    session: AsyncSession,
    from_relay: str,
    nonce: str,
    *,
    commit: bool = True,
) -> bool:
    """Record a federation nonce. Returns ``True`` iff new (not a replay).

    Atomic — relies on the ``(from_relay, nonce)`` composite PK to fail
    INSERT on conflict. Mirrors
    :func:`uam.db.crud.dedup.record_message_id`.

    When *commit* is ``False`` the row is flushed (so the unique constraint
    is checked) but the caller is responsible for committing the session.
    Used by ``routes/federation.py::federation_deliver`` so the nonce
    insertion lands in the same transaction as the dedup/store/log writes
    that follow.
    """
    entry = FederationNonce(from_relay=from_relay, nonce=nonce)
    session.add(entry)
    try:
        if commit:
            await session.commit()
        else:
            await session.flush()
        return True
    except IntegrityError:
        await session.rollback()
        return False


async def sweep_old_nonces(
    session: AsyncSession,
    *,
    max_age_seconds: int = 600,
) -> int:
    """Delete ``federation_nonces`` rows older than ``max_age_seconds``.

    Returns the count of deleted rows. Called by
    ``_federation_nonce_sweep_loop`` every
    ``UAM_FEDERATION_NONCE_SWEEP_INTERVAL`` seconds. The default 600s
    keeps rows around for 2× the federation timestamp freshness window
    (default 300s) — a replay arriving more than 600s after the original
    is already independently rejected by the timestamp check in
    federation_deliver Step 3.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=max_age_seconds)
    result = await session.execute(
        sa_delete(FederationNonce).where(FederationNonce.seen_at < cutoff)
    )
    await session.commit()
    return result.rowcount or 0  # type: ignore[return-value]

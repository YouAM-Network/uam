"""Per-category retention sweeps (Phase 48 Q5).

Extends the existing :func:`uam.relay.app._retention_worker_loop` with finer-
grained windows. The existing ``MESSAGE_RETENTION_DAYS`` (default 90 days,
configured in ``app.py``) remains the catch-all upper bound; this module adds
stricter per-category sweeps.

| Category              | Default window | Env var                          |
|-----------------------|----------------|----------------------------------|
| Delivered messages    | 1 day          | ``UAM_RETENTION_DELIVERED_DAYS`` |
| Undelivered messages  | 7 days         | ``UAM_RETENTION_UNDELIVERED_DAYS``|
| Federation nonces     | 1 hour         | ``UAM_RETENTION_FED_NONCE_HOURS``|
| Demo sessions         | 1 hour         | ``UAM_RETENTION_DEMO_HOURS``     |
| Auth challenges       | 5 minutes      | ``UAM_RETENTION_CHALLENGE_MINUTES``|

Each per-category sweep runs in its own ``try/except`` block — a failure
(missing table, transient DB error, etc.) is logged and the next category
proceeds.  Returns a ``dict`` of pruned-row counts for observability.

Design notes
------------

- ``demo`` and ``challenge`` are best-effort SQL sweeps. ``demo_sessions`` is
  currently kept in-memory by ``uam.relay.demo_sessions.SessionManager``
  (already pruned by ``_demo_session_cleanup_loop`` every 60s) — the SQL
  attempt below targets a future ``demo_sessions`` table; until that table
  exists the sweep logs and returns 0 for that category.
- ``auth_challenges`` lives in the **registrar's** separate aiosqlite database
  (``src/uam/registrar/database.py``), not the relay's SQLAlchemy DB. The SQL
  sweep below targets the registrar's table name in case it is ever migrated
  into the relay DB; today it logs and returns 0 because the table does not
  exist on the relay engine.
- ``federation_nonces`` exists (Phase 45 schema, columns
  ``from_relay``/``nonce``/``seen_at``) and is the primary new sweep target
  alongside the per-status message windows.

All five DELETE statements use parameterized SQL (cutoffs bound as parameters,
table/column names are static literals).
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Per-category retention windows (env-tunable, all have safe defaults).
#
# Defaults pinned by Wave 0 contract test
# ``test_default_windows_match_research``.  An operator who wants tighter or
# looser windows can override via env vars; values are parsed as ``int`` at
# import time and a missing/garbage env var falls back to the default below.
# ---------------------------------------------------------------------------


def _int_env(name: str, default: int) -> int:
    """Parse ``int(os.environ[name])``; return *default* on missing/invalid."""
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except ValueError:
        logger.warning(
            "retention: env %s=%r is not an int; using default %d",
            name,
            raw,
            default,
        )
        return default


RETENTION_DELIVERED_DAYS: int = _int_env("UAM_RETENTION_DELIVERED_DAYS", 1)
RETENTION_UNDELIVERED_DAYS: int = _int_env("UAM_RETENTION_UNDELIVERED_DAYS", 7)
RETENTION_FED_NONCE_HOURS: int = _int_env("UAM_RETENTION_FED_NONCE_HOURS", 1)
RETENTION_DEMO_HOURS: int = _int_env("UAM_RETENTION_DEMO_HOURS", 1)
RETENTION_CHALLENGE_MINUTES: int = _int_env("UAM_RETENTION_CHALLENGE_MINUTES", 5)


async def _sweep_one(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    category: str,
    sql: str,
    params: dict,
) -> int:
    """Run one DELETE in its own session; return rowcount.

    Per-category isolation is real: each sweep gets a fresh session. A
    failure in one category (missing table, transient DB error, etc.) is
    logged and yields ``0`` — it cannot rollback or otherwise affect the
    rows committed by sibling categories that already ran.
    """
    try:
        async with session_factory() as session:
            result = await session.execute(text(sql), params)
            count = int(getattr(result, "rowcount", 0) or 0)
            await session.commit()
        logger.info("retention.%s_pruned rows=%d", category, count)
        return count
    except Exception:
        # The ``async with`` block above will have already rolled back the
        # failed transaction on context exit. Nothing else to do besides log
        # and return 0 so the caller can keep going.
        logger.exception("retention.%s_error", category)
        return 0


async def run_retention_sweep(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    now: Optional[datetime] = None,
) -> dict[str, int]:
    """Run all per-category retention sweeps.

    Args:
        session_factory: An ``async_sessionmaker`` bound to the relay engine
            (typically ``app.state.session_factory``).  Tests pass a factory
            bound to a temporary file engine.
        now: Optional UTC override (tests).  Defaults to ``datetime.now(tz=
            timezone.utc)`` so cutoffs are tz-aware and match the
            ``DateTime(timezone=True)`` columns on the models.

    Returns:
        Dict mapping category name to count of pruned rows.  Categories whose
        tables do not exist on the configured engine (e.g. ``demo_sessions``
        and ``auth_challenges`` today) return ``0`` and log the error rather
        than aborting the sweep.
    """
    now = now or datetime.now(tz=timezone.utc)
    results: dict[str, int] = {}

    # 1. Delivered messages — drop after DELIVERED_DAYS.
    results["delivered"] = await _sweep_one(
        session_factory,
        category="delivered",
        sql=(
            "DELETE FROM messages "
            "WHERE delivered_at IS NOT NULL "
            "AND delivered_at < :cutoff"
        ),
        params={
            "cutoff": now - timedelta(days=RETENTION_DELIVERED_DAYS),
        },
    )

    # 2. Undelivered messages — drop after UNDELIVERED_DAYS based on
    #    creation time. The 90-day catch-all in app.py uses the same
    #    column for status='expired'/'delivered' rows; this stricter
    #    sweep targets queued-but-undelivered messages.
    results["undelivered"] = await _sweep_one(
        session_factory,
        category="undelivered",
        sql=(
            "DELETE FROM messages "
            "WHERE delivered_at IS NULL "
            "AND created_at < :cutoff"
        ),
        params={
            "cutoff": now - timedelta(days=RETENTION_UNDELIVERED_DAYS),
        },
    )

    # 3. Federation nonces (Phase 45 ``federation_nonces`` table —
    #    columns from_relay/nonce/seen_at).  This sweep is stricter
    #    than the existing ``_federation_nonce_sweep_loop`` (default
    #    600s) — operator can tune via env var.
    results["fed_nonce"] = await _sweep_one(
        session_factory,
        category="fed_nonce",
        sql=(
            "DELETE FROM federation_nonces "
            "WHERE seen_at < :cutoff"
        ),
        params={
            "cutoff": now - timedelta(hours=RETENTION_FED_NONCE_HOURS),
        },
    )

    # 4. Demo sessions — placeholder SQL targets a future ``demo_sessions``
    #    table.  Today the SessionManager in
    #    ``uam.relay.demo_sessions`` keeps demo state in memory and
    #    ``_demo_session_cleanup_loop`` prunes it every 60s. The
    #    per-category exception handler swallows the missing table and
    #    returns 0 until/unless the data is migrated to a table.
    results["demo"] = await _sweep_one(
        session_factory,
        category="demo",
        sql=(
            "DELETE FROM demo_sessions "
            "WHERE created_at < :cutoff"
        ),
        params={
            "cutoff": now - timedelta(hours=RETENTION_DEMO_HOURS),
        },
    )

    # 5. Auth challenges — placeholder SQL.  ``auth_challenges`` lives
    #    in the registrar's aiosqlite DB
    #    (``uam.registrar.database``), not the relay's SQLAlchemy DB,
    #    so this sweep currently logs+returns 0 on the relay engine.
    #    Provided for forward-compat in case the table is ever moved
    #    onto the shared engine.
    results["challenge"] = await _sweep_one(
        session_factory,
        category="challenge",
        sql=(
            "DELETE FROM auth_challenges "
            "WHERE created_at < :cutoff"
        ),
        params={
            "cutoff": now - timedelta(minutes=RETENTION_CHALLENGE_MINUTES),
        },
    )

    return results


__all__ = [
    "run_retention_sweep",
    "RETENTION_DELIVERED_DAYS",
    "RETENTION_UNDELIVERED_DAYS",
    "RETENTION_FED_NONCE_HOURS",
    "RETENTION_DEMO_HOURS",
    "RETENTION_CHALLENGE_MINUTES",
]

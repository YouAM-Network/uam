"""Health check endpoints for the UAM relay.

- ``GET /health`` — Simple liveness check (no auth).
- ``GET /admin/health`` — Comprehensive diagnostics (admin key required).
"""

from __future__ import annotations

import time

from fastapi import APIRouter, Depends, Request
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from uam.db.session import get_session
from uam.relay.models import AdminHealthResponse, HealthResponse
from uam.relay.routes.admin import verify_admin_key

router = APIRouter()


@router.get("/health", response_model=HealthResponse)
async def health(request: Request) -> HealthResponse:
    """Return relay status. No authentication required."""
    manager = request.app.state.manager

    return HealthResponse(
        status="ok",
        agents_online=manager.online_count,
        version="0.1.0",
    )


@router.get("/admin/health", response_model=AdminHealthResponse)
async def admin_health(
    request: Request,
    session: AsyncSession = Depends(get_session),
    _: None = Depends(verify_admin_key),
) -> AdminHealthResponse:
    """Return comprehensive relay diagnostics. Requires admin key auth."""
    # DB connectivity check
    db_ok = True
    try:
        await session.execute(text("SELECT 1"))
    except Exception:
        db_ok = False

    # Pending message queue depth
    queue_depth = 0
    try:
        result = await session.execute(
            text(
                "SELECT COUNT(*) FROM messages "
                "WHERE status='queued' AND deleted_at IS NULL"
            )
        )
        queue_depth = result.scalar_one()
    except Exception:
        pass  # table may not exist yet

    # WebSocket connection count
    ws_connections = request.app.state.manager.online_count

    # Uptime
    startup_time = getattr(request.app.state, "startup_time", None)
    uptime_seconds = (
        time.monotonic() - startup_time if startup_time is not None else 0.0
    )

    # Migration version from alembic_version table
    migration_version: str | None = None
    try:
        result = await session.execute(
            text("SELECT version_num FROM alembic_version LIMIT 1")
        )
        row = result.first()
        if row:
            migration_version = row[0]
    except Exception:
        pass  # table may not exist

    status = "healthy" if db_ok else "degraded"

    return AdminHealthResponse(
        status=status,
        db_ok=db_ok,
        queue_depth=queue_depth,
        ws_connections=ws_connections,
        uptime_seconds=round(uptime_seconds, 2),
        migration_version=migration_version,
    )

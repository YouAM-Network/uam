"""GET /health -- relay health check endpoint."""

from __future__ import annotations

from fastapi import APIRouter, Request

from uam.relay.models import HealthResponse

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

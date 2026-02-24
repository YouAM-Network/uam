"""GET /agents/{address}/presence -- agent presence endpoint (PRES-01)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from uam.db.crud.agents import get_agent_by_address
from uam.db.session import get_session
from uam.relay.auth import verify_token_http
from uam.relay.models import PresenceResponse

router = APIRouter()


@router.get("/agents/{address}/presence", response_model=PresenceResponse)
async def get_presence(
    address: str,
    request: Request,
    agent: dict = Depends(verify_token_http),
    session: AsyncSession = Depends(get_session),
) -> PresenceResponse:
    """Check whether an agent is currently online.

    Returns the agent's online status (based on active WebSocket connection)
    and their last_seen timestamp from the database.

    Requires Bearer token authentication.
    """
    manager = request.app.state.manager

    # Look up the target agent
    target = await get_agent_by_address(session, address)
    if target is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    online = manager.is_online(address)

    return PresenceResponse(
        address=address,
        online=online,
        last_seen=target.last_seen,
    )

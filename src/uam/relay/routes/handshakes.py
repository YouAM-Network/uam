"""Handshake endpoints for relay-mediated key exchange (RELAY-11).

POST /handshakes/send -- initiate a handshake
GET /handshakes/pending/{address} -- list pending handshakes for an agent
POST /handshakes/{handshake_id}/respond -- respond to a handshake
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from uam.db.crud.handshakes import (
    create_handshake,
    get_handshake_by_id,
    get_pending,
    respond_handshake,
)
from uam.db.session import get_session
from uam.relay.auth import verify_token_http
from uam.relay.models import (
    HandshakeListResponse,
    HandshakeRespondRequest,
    HandshakeResponse,
    HandshakeSendRequest,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["handshakes"])


# ---------------------------------------------------------------------------
# POST /handshakes/send -- initiate a handshake
# ---------------------------------------------------------------------------


@router.post("/handshakes/send", response_model=HandshakeResponse, status_code=201)
async def send_handshake(
    body: HandshakeSendRequest,
    session: AsyncSession = Depends(get_session),
    agent: dict = Depends(verify_token_http),
) -> HandshakeResponse:
    """Initiate a relay-mediated handshake with another agent.

    Creates a pending handshake request from the authenticated agent
    to the target address.  Optionally includes a contact card.
    """
    # --- Transaction-wrapped DB section (RES-01) ---
    try:
        hs = await create_handshake(
            session,
            from_addr=agent["address"],
            to_addr=body.to_address,
            contact_card=body.contact_card,
            commit=False,
        )
        await session.commit()
    except Exception:
        await session.rollback()
        raise

    return HandshakeResponse(
        id=hs.id,  # type: ignore[arg-type]
        status=hs.status,
        from_addr=hs.from_addr,
        to_addr=hs.to_addr,
    )


# ---------------------------------------------------------------------------
# GET /handshakes/pending/{address} -- list pending handshakes
# ---------------------------------------------------------------------------


@router.get("/handshakes/pending/{address}", response_model=HandshakeListResponse)
async def list_pending_handshakes(
    address: str,
    session: AsyncSession = Depends(get_session),
    agent: dict = Depends(verify_token_http),
) -> HandshakeListResponse:
    """List pending handshakes for the authenticated agent.

    Agent can only view their own pending handshakes (incoming).
    """
    if agent["address"] != address:
        raise HTTPException(
            status_code=403,
            detail="Cannot view another agent's pending handshakes",
        )

    pending = await get_pending(session, address)
    items = [
        HandshakeResponse(
            id=hs.id,  # type: ignore[arg-type]
            status=hs.status,
            from_addr=hs.from_addr,
            to_addr=hs.to_addr,
        )
        for hs in pending
    ]
    return HandshakeListResponse(handshakes=items, count=len(items))


# ---------------------------------------------------------------------------
# POST /handshakes/{handshake_id}/respond -- respond to a handshake
# ---------------------------------------------------------------------------


@router.post("/handshakes/{handshake_id}/respond", response_model=HandshakeResponse)
async def respond_to_handshake(
    handshake_id: int,
    body: HandshakeRespondRequest,
    session: AsyncSession = Depends(get_session),
    agent: dict = Depends(verify_token_http),
) -> HandshakeResponse:
    """Respond to a pending handshake (approve or deny).

    The authenticated agent must be the ``to_addr`` of the handshake.
    """
    # Validate response value
    if body.response not in ("approved", "denied"):
        raise HTTPException(
            status_code=400,
            detail="Response must be 'approved' or 'denied'",
        )

    # Look up the handshake
    hs = await get_handshake_by_id(session, handshake_id)
    if hs is None:
        raise HTTPException(
            status_code=404,
            detail=f"Handshake not found: {handshake_id}",
        )

    # Verify the authenticated agent is the recipient
    if hs.to_addr != agent["address"]:
        raise HTTPException(
            status_code=403,
            detail="Only the handshake recipient can respond",
        )

    # Check it's still pending
    if hs.status != "pending":
        raise HTTPException(
            status_code=409,
            detail=f"Handshake already resolved with status: {hs.status}",
        )

    # --- Transaction-wrapped DB section (RES-01) ---
    try:
        result = await respond_handshake(session, handshake_id, body.response, commit=False)
        if result is None:
            raise HTTPException(
                status_code=404,
                detail=f"Handshake not found: {handshake_id}",
            )
        await session.commit()
    except HTTPException:
        await session.rollback()
        raise
    except Exception:
        await session.rollback()
        raise

    return HandshakeResponse(
        id=result.id,  # type: ignore[arg-type]
        status=result.status,
        from_addr=result.from_addr,
        to_addr=result.to_addr,
    )

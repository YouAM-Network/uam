"""Agent endpoints: public-key lookup (unauthenticated), card file serving,
and agent management (PATCH/DELETE/reactivate, authenticated).

Public-key lookup is **unauthenticated** by design -- an agent sending its
very first message (``handshake.request``) needs the recipient's public
key for SealedBox encryption *before* it has exchanged credentials.

Card serving endpoints (card.vcf, card.png) are also unauthenticated --
identity vCards and card images are public-facing for viral sharing.
"""

from __future__ import annotations

import hashlib
import logging

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.responses import Response

from uam.cards.image import render_card
from uam.cards.vcard import generate_identity_vcard
from uam.db.crud.agents import (
    deactivate_agent,
    get_agent_by_address,
    reactivate_agent,
    update_agent,
)
from uam.db.crud.domain_verification import get_verification
from uam.db.session import get_session
from uam.protocol.crypto import deserialize_verify_key
from uam.relay.auth import verify_token_http
from uam.relay.models import AgentResponse, PublicKeyResponse, UpdateAgentRequest

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/agents/{address}/public-key", response_model=PublicKeyResponse)
async def get_public_key(
    address: str,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> PublicKeyResponse:
    """Return the public key for a registered agent.

    Unauthenticated -- any caller can look up any agent's public key.
    This is required for encrypting the first message (handshake.request)
    when the sender has no prior relationship with the recipient.
    """
    target = await get_agent_by_address(session, address)
    if target is None:
        raise HTTPException(status_code=404, detail=f"Agent not found: {address}")

    # Check for Tier 2 domain verification
    verification = await get_verification(session, address)
    if verification:
        return PublicKeyResponse(
            address=address,
            public_key=target.public_key,
            tier=2,
            verified_domain=verification.domain,
        )

    return PublicKeyResponse(address=address, public_key=target.public_key)


# ---------------------------------------------------------------------------
# Helper: convert Agent model to AgentResponse
# ---------------------------------------------------------------------------


def _agent_to_response(agent: object) -> AgentResponse:
    """Convert a SQLModel Agent to an AgentResponse."""
    return AgentResponse(
        address=agent.address,  # type: ignore[union-attr]
        public_key=agent.public_key,  # type: ignore[union-attr]
        status=agent.status,  # type: ignore[union-attr]
        display_name=getattr(agent, "display_name", None),
        webhook_url=getattr(agent, "webhook_url", None),
        last_seen=str(agent.last_seen) if getattr(agent, "last_seen", None) else None,  # type: ignore[union-attr]
        created_at=str(agent.created_at),  # type: ignore[union-attr]
    )


# ---------------------------------------------------------------------------
# RELAY-08: PATCH /agents/{address} -- update agent fields
# ---------------------------------------------------------------------------


@router.patch("/agents/{address}", response_model=AgentResponse)
async def patch_agent(
    address: str,
    body: UpdateAgentRequest,
    session: AsyncSession = Depends(get_session),
    agent: dict = Depends(verify_token_http),
) -> AgentResponse:
    """Update agent fields (display_name, contact_card, public_key).

    Requires Bearer token auth.  Agent can only update their own record.
    If ``public_key`` is provided, it must be a valid Ed25519 key.
    """
    if agent["address"] != address:
        raise HTTPException(
            status_code=403,
            detail="Cannot update another agent's record",
        )

    updates = body.model_dump(exclude_none=True)
    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")

    # Validate public key if provided
    if "public_key" in updates:
        try:
            deserialize_verify_key(updates["public_key"])
        except Exception:
            raise HTTPException(
                status_code=400,
                detail="Invalid Ed25519 public key",
            )

    updated = await update_agent(session, address, **updates)
    if updated is None:
        raise HTTPException(status_code=404, detail=f"Agent not found: {address}")

    return _agent_to_response(updated)


# ---------------------------------------------------------------------------
# RELAY-09: DELETE /agents/{address} -- soft-deactivate agent
# ---------------------------------------------------------------------------


@router.delete("/agents/{address}")
async def delete_agent(
    address: str,
    session: AsyncSession = Depends(get_session),
    agent: dict = Depends(verify_token_http),
) -> dict:
    """Soft-deactivate an agent.

    Requires Bearer token auth.  Agent can only deactivate themselves.
    """
    if agent["address"] != address:
        raise HTTPException(
            status_code=403,
            detail="Cannot deactivate another agent",
        )

    result = await deactivate_agent(session, address)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Agent not found: {address}")

    return {"status": "deactivated", "address": address}


# ---------------------------------------------------------------------------
# RELAY-15: POST /agents/{address}/reactivate -- restore soft-deleted agent
# ---------------------------------------------------------------------------


@router.post("/agents/{address}/reactivate", response_model=AgentResponse)
async def reactivate_agent_endpoint(
    address: str,
    session: AsyncSession = Depends(get_session),
    agent: dict = Depends(verify_token_http),
) -> AgentResponse:
    """Reactivate a soft-deleted agent.

    Requires Bearer token auth.  The token must match the original agent's
    token (auth does not filter by deleted_at so soft-deleted agents can
    still authenticate for reactivation).
    """
    if agent["address"] != address:
        raise HTTPException(
            status_code=403,
            detail="Cannot reactivate another agent",
        )

    result = await reactivate_agent(session, address)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Agent not found: {address}")

    if result.status != "active":
        raise HTTPException(
            status_code=409,
            detail="Agent was not deactivated",
        )

    return _agent_to_response(result)


# ---------------------------------------------------------------------------
# VCF-05: GET /agents/{address}/card.vcf -- identity vCard download
# ---------------------------------------------------------------------------


@router.get("/agents/{address}/card.vcf")
async def get_agent_vcf(
    address: str,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> Response:
    """Download the identity vCard for a registered agent (VCF-05).

    Returns a vCard 3.0 file with the agent's identity card image embedded
    as PHOTO, plus X-UAM-* fields for programmatic use.
    """
    agent = await get_agent_by_address(session, address)
    if agent is None:
        raise HTTPException(status_code=404, detail=f"Agent not found: {address}")

    settings = request.app.state.settings
    agent_name = address.split("::")[0]

    # Generate fingerprint from public key (first 32 chars of hex)
    fingerprint = hashlib.sha256(agent.public_key.encode()).hexdigest()[:32]

    vcf_content = generate_identity_vcard(
        agent_name=agent_name,
        relay_domain=settings.relay_domain,
        public_key_b64=agent.public_key,
        fingerprint=fingerprint,
    )

    filename = f"{agent_name}.vcf"
    return Response(
        content=vcf_content,
        media_type="text/vcard",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
        },
    )


# ---------------------------------------------------------------------------
# CARD-06: GET /agents/{address}/card.png -- identity card image
# ---------------------------------------------------------------------------


@router.get("/agents/{address}/card.png")
async def get_agent_card_image(
    address: str,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> Response:
    """Serve the identity card image for a registered agent (CARD-06).

    Returns a 600x600 JPEG image with Cache-Control headers for CDN caching.
    Note: The endpoint path says .png but serves JPEG for size efficiency --
    the card renderer produces JPEG (under 200KB).
    """
    agent = await get_agent_by_address(session, address)
    if agent is None:
        raise HTTPException(status_code=404, detail=f"Agent not found: {address}")

    settings = request.app.state.settings
    agent_name = address.split("::")[0]

    fingerprint = hashlib.sha256(agent.public_key.encode()).hexdigest()[:32]

    image_bytes = render_card(
        agent_name=agent_name,
        relay_domain=settings.relay_domain,
        card_type="identity",
        fingerprint=fingerprint,
    )

    return Response(
        content=image_bytes,
        media_type="image/jpeg",
        headers={
            "Cache-Control": "public, max-age=3600",
        },
    )

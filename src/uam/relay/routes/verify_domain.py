"""POST /verify-domain -- domain ownership verification endpoint (DNS-04).

Also provides GET /agents/{address}/verification for querying
verification status (public, unauthenticated).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from uam.db.crud.agents import get_agent_by_address
from uam.db.crud.domain_verification import get_verification, upsert_verification
from uam.db.session import get_session
from uam.relay.auth import verify_token_http
from uam.relay.models import VerifyDomainRequest, VerifyDomainResponse
from uam.relay.verification import verify_domain_ownership

router = APIRouter()


@router.post("/verify-domain", response_model=VerifyDomainResponse)
async def verify_domain(
    body: VerifyDomainRequest,
    request: Request,
    agent: dict = Depends(verify_token_http),
    session: AsyncSession = Depends(get_session),
) -> VerifyDomainResponse:
    """Verify domain ownership for Tier 2 status (DNS-04).

    Requires Bearer token authentication.  The relay independently
    verifies that the agent's public key appears in the domain's DNS
    TXT record or HTTPS ``.well-known/uam.json`` file.
    """
    settings = request.app.state.settings

    success, method, detail = await verify_domain_ownership(
        body.domain, agent["public_key"], agent["address"]
    )

    if success:
        await upsert_verification(
            session,
            agent_address=agent["address"],
            domain=body.domain,
            public_key=agent["public_key"],
            method=method,
            ttl_hours=settings.domain_verification_ttl_hours,
        )
        # Upgrade reputation for DNS-verified agents (SPAM-02)
        reputation_manager = request.app.state.reputation_manager
        await reputation_manager.set_score(agent["address"], 60)
        return VerifyDomainResponse(
            status="verified", domain=body.domain, tier=2
        )

    return VerifyDomainResponse(
        status="failed", domain=body.domain, tier=1, detail=detail
    )


@router.get("/agents/{address}/verification")
async def get_verification_status(
    address: str,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Return verification status for an agent (public, no auth required).

    Returns ``{"address": ..., "tier": 1|2, "domain": ...}``
    or 404 if the agent is not registered.
    """
    agent = await get_agent_by_address(session, address)
    if agent is None:
        raise HTTPException(status_code=404, detail=f"Agent not found: {address}")

    verification = await get_verification(session, address)
    if verification:
        return {
            "address": address,
            "tier": 2,
            "domain": verification.domain,
        }

    return {"address": address, "tier": 1, "domain": None}

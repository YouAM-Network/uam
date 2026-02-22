"""Admin API endpoints for spam defense management (SPAM-05).

Provides CRUD endpoints for blocklist, allowlist, and reputation management.
All endpoints require ``X-Admin-Key`` header authentication with constant-time
comparison via ``hmac.compare_digest()``.
"""

from __future__ import annotations

import hmac
import logging

from fastapi import APIRouter, Depends, HTTPException, Request

from uam.relay.models import (
    AllowlistEntry,
    AllowlistListResponse,
    AllowlistRequest,
    BlocklistEntry,
    BlocklistListResponse,
    BlocklistRequest,
    ReputationResponse,
    SetReputationRequest,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/admin", tags=["admin"])


# ---------------------------------------------------------------------------
# Auth dependency
# ---------------------------------------------------------------------------


async def verify_admin_key(request: Request) -> None:
    """FastAPI dependency: validate X-Admin-Key header.

    - Returns 503 if ``UAM_ADMIN_API_KEY`` is not configured on the server.
    - Returns 401 if the header is missing or does not match.
    - Uses ``hmac.compare_digest()`` for constant-time comparison.
    """
    configured_key = request.app.state.settings.admin_api_key
    if configured_key is None:
        raise HTTPException(status_code=503, detail="Admin API not configured")

    provided_key = request.headers.get("X-Admin-Key")
    if provided_key is None or not hmac.compare_digest(provided_key, configured_key):
        raise HTTPException(status_code=401, detail="Invalid admin API key")


# ---------------------------------------------------------------------------
# Blocklist endpoints (SPAM-01, SPAM-05)
# ---------------------------------------------------------------------------


@router.post("/blocklist", status_code=201)
async def add_blocked(
    body: BlocklistRequest,
    request: Request,
    _: None = Depends(verify_admin_key),
) -> dict:
    """Add a pattern to the blocklist."""
    if "::" not in body.pattern:
        raise HTTPException(
            status_code=400,
            detail="Pattern must contain '::' (e.g. 'name::domain' or '*::domain')",
        )
    db = request.app.state.db
    spam_filter = request.app.state.spam_filter
    await spam_filter.add_blocked(db, body.pattern, body.reason)
    return {"pattern": body.pattern, "status": "added"}


@router.delete("/blocklist/{pattern:path}")
async def remove_blocked(
    pattern: str,
    request: Request,
    _: None = Depends(verify_admin_key),
) -> dict:
    """Remove a pattern from the blocklist."""
    db = request.app.state.db
    spam_filter = request.app.state.spam_filter
    removed = await spam_filter.remove_blocked(db, pattern)
    if not removed:
        raise HTTPException(status_code=404, detail="Pattern not found in blocklist")
    return {"pattern": pattern, "status": "removed"}


@router.get("/blocklist", response_model=BlocklistListResponse)
async def list_blocked(
    request: Request,
    _: None = Depends(verify_admin_key),
) -> BlocklistListResponse:
    """List all blocklist entries."""
    db = request.app.state.db
    spam_filter = request.app.state.spam_filter
    entries = await spam_filter.list_blocked(db)
    return BlocklistListResponse(
        entries=[BlocklistEntry(**e) for e in entries],
        count=len(entries),
    )


# ---------------------------------------------------------------------------
# Allowlist endpoints (SPAM-01, SPAM-05)
# ---------------------------------------------------------------------------


@router.post("/allowlist", status_code=201)
async def add_allowed(
    body: AllowlistRequest,
    request: Request,
    _: None = Depends(verify_admin_key),
) -> dict:
    """Add a pattern to the allowlist."""
    if "::" not in body.pattern:
        raise HTTPException(
            status_code=400,
            detail="Pattern must contain '::' (e.g. 'name::domain' or '*::domain')",
        )
    db = request.app.state.db
    spam_filter = request.app.state.spam_filter
    await spam_filter.add_allowed(db, body.pattern, body.reason)
    return {"pattern": body.pattern, "status": "added"}


@router.delete("/allowlist/{pattern:path}")
async def remove_allowed(
    pattern: str,
    request: Request,
    _: None = Depends(verify_admin_key),
) -> dict:
    """Remove a pattern from the allowlist."""
    db = request.app.state.db
    spam_filter = request.app.state.spam_filter
    removed = await spam_filter.remove_allowed(db, pattern)
    if not removed:
        raise HTTPException(status_code=404, detail="Pattern not found in allowlist")
    return {"pattern": pattern, "status": "removed"}


@router.get("/allowlist", response_model=AllowlistListResponse)
async def list_allowed(
    request: Request,
    _: None = Depends(verify_admin_key),
) -> AllowlistListResponse:
    """List all allowlist entries."""
    db = request.app.state.db
    spam_filter = request.app.state.spam_filter
    entries = await spam_filter.list_allowed(db)
    return AllowlistListResponse(
        entries=[AllowlistEntry(**e) for e in entries],
        count=len(entries),
    )


# ---------------------------------------------------------------------------
# Reputation endpoints (SPAM-05)
# ---------------------------------------------------------------------------


@router.get("/reputation/{address:path}", response_model=ReputationResponse)
async def get_reputation(
    address: str,
    request: Request,
    _: None = Depends(verify_admin_key),
) -> ReputationResponse:
    """Inspect agent reputation."""
    reputation_manager = request.app.state.reputation_manager
    info = await reputation_manager.get_reputation_info(address)
    if info is None:
        raise HTTPException(status_code=404, detail="No reputation record for address")
    tier = reputation_manager.get_tier(address)
    return ReputationResponse(
        address=info["address"],
        score=info["score"],
        tier=tier,
        messages_sent=info["messages_sent"],
        messages_rejected=info["messages_rejected"],
        created_at=info["created_at"],
        updated_at=info["updated_at"],
    )


@router.put("/reputation/{address:path}", response_model=ReputationResponse)
async def set_reputation(
    address: str,
    body: SetReputationRequest,
    request: Request,
    _: None = Depends(verify_admin_key),
) -> ReputationResponse:
    """Admin override of reputation score."""
    if body.score < 0 or body.score > 100:
        raise HTTPException(
            status_code=400, detail="Score must be between 0 and 100"
        )
    reputation_manager = request.app.state.reputation_manager
    await reputation_manager.set_score(address, body.score)
    # Fetch the updated record
    info = await reputation_manager.get_reputation_info(address)
    if info is None:
        raise HTTPException(status_code=404, detail="No reputation record for address")
    tier = reputation_manager.get_tier(address)
    return ReputationResponse(
        address=info["address"],
        score=info["score"],
        tier=tier,
        messages_sent=info["messages_sent"],
        messages_rejected=info["messages_rejected"],
        created_at=info["created_at"],
        updated_at=info["updated_at"],
    )

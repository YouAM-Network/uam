"""Admin API endpoints for spam defense and relay management.

Provides CRUD endpoints for blocklist, allowlist, reputation management
(SPAM-05), and expanded admin endpoints for agent listing, suspension,
audit log, and message purging (RELAY-12).

All endpoints require ``X-Admin-Key`` header authentication with constant-time
comparison via ``hmac.compare_digest()``.
"""

from __future__ import annotations

import hmac
import logging

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession

from uam.db.crud.agents import list_agents_with_deleted, suspend_agent
from uam.db.crud.audit import query_audit_log
from uam.db.crud.messages import purge_expired
from uam.db.session import get_session
from uam.relay.models import (
    AdminAgentListResponse,
    AdminAgentResponse,
    AllowlistEntry,
    AllowlistListResponse,
    AllowlistRequest,
    AuditLogEntry,
    AuditLogResponse,
    BlocklistEntry,
    BlocklistListResponse,
    BlocklistRequest,
    PurgeExpiredResponse,
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
    session: AsyncSession = Depends(get_session),
    _: None = Depends(verify_admin_key),
) -> dict:
    """Add a pattern to the blocklist."""
    if "::" not in body.pattern:
        raise HTTPException(
            status_code=400,
            detail="Pattern must contain '::' (e.g. 'name::domain' or '*::domain')",
        )
    spam_filter = request.app.state.spam_filter
    await spam_filter.add_blocked(session, body.pattern, body.reason)
    return {"pattern": body.pattern, "status": "added"}


@router.delete("/blocklist/{pattern:path}")
async def remove_blocked(
    pattern: str,
    request: Request,
    session: AsyncSession = Depends(get_session),
    _: None = Depends(verify_admin_key),
) -> dict:
    """Remove a pattern from the blocklist."""
    spam_filter = request.app.state.spam_filter
    removed = await spam_filter.remove_blocked(session, pattern)
    if not removed:
        raise HTTPException(status_code=404, detail="Pattern not found in blocklist")
    return {"pattern": pattern, "status": "removed"}


@router.get("/blocklist", response_model=BlocklistListResponse)
async def list_blocked(
    request: Request,
    session: AsyncSession = Depends(get_session),
    _: None = Depends(verify_admin_key),
) -> BlocklistListResponse:
    """List all blocklist entries."""
    spam_filter = request.app.state.spam_filter
    entries = await spam_filter.list_blocked(session)
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
    session: AsyncSession = Depends(get_session),
    _: None = Depends(verify_admin_key),
) -> dict:
    """Add a pattern to the allowlist."""
    if "::" not in body.pattern:
        raise HTTPException(
            status_code=400,
            detail="Pattern must contain '::' (e.g. 'name::domain' or '*::domain')",
        )
    spam_filter = request.app.state.spam_filter
    await spam_filter.add_allowed(session, body.pattern, body.reason)
    return {"pattern": body.pattern, "status": "added"}


@router.delete("/allowlist/{pattern:path}")
async def remove_allowed(
    pattern: str,
    request: Request,
    session: AsyncSession = Depends(get_session),
    _: None = Depends(verify_admin_key),
) -> dict:
    """Remove a pattern from the allowlist."""
    spam_filter = request.app.state.spam_filter
    removed = await spam_filter.remove_allowed(session, pattern)
    if not removed:
        raise HTTPException(status_code=404, detail="Pattern not found in allowlist")
    return {"pattern": pattern, "status": "removed"}


@router.get("/allowlist", response_model=AllowlistListResponse)
async def list_allowed(
    request: Request,
    session: AsyncSession = Depends(get_session),
    _: None = Depends(verify_admin_key),
) -> AllowlistListResponse:
    """List all allowlist entries."""
    spam_filter = request.app.state.spam_filter
    entries = await spam_filter.list_allowed(session)
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


# ---------------------------------------------------------------------------
# Expanded admin endpoints (RELAY-12)
# ---------------------------------------------------------------------------


def _agent_to_admin_response(agent: object) -> AdminAgentResponse:
    """Convert a SQLModel Agent to an AdminAgentResponse."""
    return AdminAgentResponse(
        address=agent.address,  # type: ignore[union-attr]
        public_key=agent.public_key,  # type: ignore[union-attr]
        status=agent.status,  # type: ignore[union-attr]
        display_name=getattr(agent, "display_name", None),
        webhook_url=getattr(agent, "webhook_url", None),
        last_seen=str(agent.last_seen) if getattr(agent, "last_seen", None) else None,  # type: ignore[union-attr]
        created_at=str(agent.created_at),  # type: ignore[union-attr]
        updated_at=str(agent.updated_at),  # type: ignore[union-attr]
        deleted_at=str(agent.deleted_at) if getattr(agent, "deleted_at", None) else None,  # type: ignore[union-attr]
    )


@router.get("/agents", response_model=AdminAgentListResponse)
async def admin_list_agents(
    session: AsyncSession = Depends(get_session),
    _: None = Depends(verify_admin_key),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> AdminAgentListResponse:
    """List all agents (including soft-deleted) for admin inspection."""
    agents = await list_agents_with_deleted(session, limit=limit, offset=offset)
    items = [_agent_to_admin_response(a) for a in agents]
    return AdminAgentListResponse(agents=items, count=len(items))


@router.post("/agents/{address}/suspend")
async def admin_suspend_agent(
    address: str,
    session: AsyncSession = Depends(get_session),
    _: None = Depends(verify_admin_key),
) -> AdminAgentResponse:
    """Suspend an agent (admin action)."""
    result = await suspend_agent(session, address)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Agent not found: {address}")
    return _agent_to_admin_response(result)


@router.get("/audit", response_model=AuditLogResponse)
async def admin_audit_log(
    session: AsyncSession = Depends(get_session),
    _: None = Depends(verify_admin_key),
    action: str | None = Query(default=None),
    entity_type: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> AuditLogResponse:
    """Query the audit log with optional filters."""
    entries = await query_audit_log(
        session,
        action=action,
        entity_type=entity_type,
        limit=limit,
        offset=offset,
    )
    items = [
        AuditLogEntry(
            id=e.id,  # type: ignore[arg-type]
            action=e.action,
            entity_type=e.entity_type,
            entity_id=e.entity_id,
            actor_address=e.actor_address,
            timestamp=str(e.timestamp),
            details=e.details,
            ip_address=e.ip_address,
        )
        for e in entries
    ]
    return AuditLogResponse(entries=items, count=len(items))


@router.delete("/messages/expired", response_model=PurgeExpiredResponse)
async def admin_purge_expired_messages(
    session: AsyncSession = Depends(get_session),
    _: None = Depends(verify_admin_key),
) -> PurgeExpiredResponse:
    """Purge expired and old delivered/soft-deleted messages."""
    count = await purge_expired(session)
    return PurgeExpiredResponse(purged=count)

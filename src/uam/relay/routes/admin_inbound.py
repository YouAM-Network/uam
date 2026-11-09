"""Admin routes for an agent's inbound policy and contacts (P1).

The delivery gate ships dark: in P1 only the relay admin can gate an agent
(staging, tests). Owners get their own routes in P2; no agent token can
set a policy or a contact row at any phase.
"""

from __future__ import annotations

from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from uam.db.crud.agents import get_agent_by_address
from uam.db.crud.audit import log_action
from uam.db.crud.inbound import (
    RevisionMismatch,
    delete_contact,
    get_policy,
    list_contacts,
    put_contact,
    set_policy,
)
from uam.db.session import get_session
from uam.relay.routes.admin import verify_admin_key

router = APIRouter(prefix="/admin/agents", tags=["admin"])


class InboundContactView(BaseModel):
    address: str
    key: str
    state: str
    source: str
    expires_at: str | None


class InboundView(BaseModel):
    policy: str
    revision: int
    contacts: list[InboundContactView]


class PolicyRequest(BaseModel):
    policy: Literal["open", "contacts", "closed"]


class ContactRequest(BaseModel):
    key: Annotated[str, Field(min_length=1, max_length=64)]
    state: Literal["allowed", "blocked"]


class RevisionResponse(BaseModel):
    revision: int


async def _agent_or_404(session: AsyncSession, address: str) -> None:
    if await get_agent_by_address(session, address) is None:
        raise HTTPException(status_code=404, detail=f"Agent not found: {address}")


@router.get("/{address}/inbound", response_model=InboundView)
async def admin_get_inbound(
    address: str,
    session: AsyncSession = Depends(get_session),
    _: None = Depends(verify_admin_key),
    limit: int = Query(default=500, ge=1, le=5000),
    offset: int = Query(default=0, ge=0),
) -> InboundView:
    await _agent_or_404(session, address)
    policy = await get_policy(session, address)
    contacts = await list_contacts(session, address, limit=limit, offset=offset)
    return InboundView(
        policy=policy.policy if policy else "open",
        revision=policy.revision if policy else 0,
        contacts=[
            InboundContactView(
                address=c.contact_address,
                key=c.contact_key,
                state=c.state,
                source=c.source,
                expires_at=c.expires_at.isoformat() if c.expires_at else None,
            )
            for c in contacts
        ],
    )


@router.put("/{address}/inbound/policy", response_model=RevisionResponse)
async def admin_set_policy(
    address: str,
    body: PolicyRequest,
    if_match: str | None = Header(default=None),
    session: AsyncSession = Depends(get_session),
    _: None = Depends(verify_admin_key),
) -> RevisionResponse:
    if if_match is None:
        raise HTTPException(status_code=428, detail="If-Match: <revision> is required")
    try:
        expected = int(if_match.strip('"'))
    except ValueError:
        raise HTTPException(status_code=400, detail="If-Match must be a revision number") from None
    await _agent_or_404(session, address)
    try:
        revision = await set_policy(
            session, address, body.policy, expected_revision=expected, set_by="admin"
        )
    except RevisionMismatch as exc:
        raise HTTPException(
            status_code=412, detail=f"Revision changed (now {exc.current})"
        ) from None
    await log_action(
        session, "inbound_policy_set", "agent", address,
        details={"policy": body.policy, "revision": revision},
    )
    return RevisionResponse(revision=revision)


@router.put("/{address}/inbound/contacts/{contact}", response_model=RevisionResponse)
async def admin_put_contact(
    address: str,
    contact: str,
    body: ContactRequest,
    session: AsyncSession = Depends(get_session),
    _: None = Depends(verify_admin_key),
) -> RevisionResponse:
    await _agent_or_404(session, address)
    revision = await put_contact(
        session, address, contact, key=body.key, state=body.state, source="admin"
    )
    await log_action(
        session, "inbound_contact_set", "agent", address,
        details={"contact": contact, "state": body.state, "revision": revision},
    )
    return RevisionResponse(revision=revision)


@router.delete("/{address}/inbound/contacts/{contact}", response_model=RevisionResponse)
async def admin_delete_contact(
    address: str,
    contact: str,
    session: AsyncSession = Depends(get_session),
    _: None = Depends(verify_admin_key),
) -> RevisionResponse:
    await _agent_or_404(session, address)
    revision = await delete_contact(session, address, contact)
    if revision is None:
        raise HTTPException(status_code=404, detail=f"No contact row for {contact}")
    await log_action(
        session, "inbound_contact_removed", "agent", address,
        details={"contact": contact, "revision": revision},
    )
    return RevisionResponse(revision=revision)

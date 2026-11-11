"""The agent's side of linking to an owner (P2d), and the admin unlink.

An agent redeems its owner's code, or asks an email address to own it
(P2s-3); signs the link body the relay built; can cancel its link before
it starts; and can read its link's state (for its banners). There is no
route for an agent to unlink itself or to approve anything. Anyone can
read the relay's revocation list. 404 while UAM_OWNERS_ENABLED is off.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from uam.db.models import Agent
from uam.db.session import get_session
from uam.relay.auth import verify_token_http
from uam.relay.owners import contacts, links, requests
from uam.relay.owners.crypto import normalise_email
from uam.relay.owners.passkeys import PasskeyError
from uam.relay.rate_limit import SlidingWindowCounter
from uam.relay.routes.admin import verify_admin_key
from uam.relay.routes.admin_owners import owners_enabled

router = APIRouter(prefix="/owner", tags=["owners"], dependencies=[Depends(owners_enabled)])
admin_router = APIRouter(
    prefix="/admin/links",
    tags=["admin"],
    dependencies=[Depends(owners_enabled), Depends(verify_admin_key)],
)


class StartLink(BaseModel):
    code: Annotated[str, Field(max_length=32)]


class RequestOwner(BaseModel):
    email: Annotated[str, Field(max_length=320)]


#: Requests one client address can make in an hour, across its agents.
REQUESTS_PER_IP_HOUR = 10


class SignLink(BaseModel):
    hash: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{43}$")]
    signature: Annotated[str, Field(max_length=128)]


def _refused(exc: PasskeyError) -> JSONResponse:
    return JSONResponse({"error": exc.code, "detail": exc.detail}, status_code=exc.status)


async def _agent(session: AsyncSession, who: dict) -> Agent:
    return await session.get(Agent, who["address"])


@router.post("/link/start")
async def start(
    body: StartLink, request: Request,
    who: dict = Depends(verify_token_http), session: AsyncSession = Depends(get_session),
) -> Response:
    app = request.app
    try:
        return JSONResponse(await links.start(
            session, app.state.settings, app.state.owner_vault, await _agent(session, who), body.code,
        ))
    except PasskeyError as exc:
        return _refused(exc)


def _request_sink(state) -> requests.RequestSink:
    sink = getattr(state, "owner_request_sink", None)
    if sink is not None:
        return sink
    return requests.log_sink if state.settings.owner_codes_to_log else requests.drop_sink


@router.post("/link/request", status_code=202)
async def request_owner(
    body: RequestOwner, request: Request,
    who: dict = Depends(verify_token_http), session: AsyncSession = Depends(get_session),
) -> Response:
    """Ask an email address to own this agent. The answer is the same
    whether or not it has an account, and whether or not an email went out."""
    email = normalise_email(body.email)
    if email is None:
        raise HTTPException(status_code=422, detail="not an email address")
    state = request.app.state
    limiter = getattr(state, "owner_request_limiter", None)
    if limiter is None:
        limiter = state.owner_request_limiter = SlidingWindowCounter(
            limit=REQUESTS_PER_IP_HOUR, window_seconds=3600.0
        )
    if not await limiter.check(request.client.host if request.client else "unknown"):
        return JSONResponse(
            {"error": "too_many", "detail": "Too many requests from here. Try again later."},
            status_code=429,
        )
    try:
        return JSONResponse(await requests.ask(
            session, state.settings, state.owner_vault, await _agent(session, who), email,
            _request_sink(state),
        ), status_code=202)
    except PasskeyError as exc:
        return _refused(exc)


@router.post("/link/sign")
async def sign(
    body: SignLink, request: Request,
    who: dict = Depends(verify_token_http), session: AsyncSession = Depends(get_session),
) -> Response:
    notice = getattr(request.app.state, "owner_link_notice", None) or links.log_notice
    try:
        return JSONResponse(await links.agent_sign(
            session, await _agent(session, who), body.hash, body.signature, notice,
        ))
    except PasskeyError as exc:
        return _refused(exc)


@router.post("/link/cancel")
async def cancel(
    request: Request,
    who: dict = Depends(verify_token_http), session: AsyncSession = Depends(get_session),
) -> Response:
    """End this agent's link before it starts (it never unlinks itself)."""
    notice = getattr(request.app.state, "owner_link_notice", None) or links.log_notice
    try:
        return JSONResponse(await links.agent_cancel(session, await _agent(session, who), notice))
    except PasskeyError as exc:
        return _refused(exc)


@router.get("/link")
async def status(
    request: Request,
    who: dict = Depends(verify_token_http), session: AsyncSession = Depends(get_session),
) -> dict:
    agent = await _agent(session, who)
    status = await links.agent_status(session, request.app.state.owner_vault, agent)
    return {**status, **(await requests.agent_view(session, request.app.state.settings, agent) or {})}


@router.get("/revocations")
async def revocations(
    request: Request,
    since: Annotated[int, Query(ge=0, le=2**53 - 1)] = 0,
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Grants and invites this relay revoked, after entry *since* (P2e). Public:
    each entry is only a type, a hash and a time. Signed by the relay's key."""
    state = request.app.state
    return await contacts.revocations(
        session, state.settings, getattr(state, "relay_signing_key", None), since
    )


@admin_router.post("/{link_id}/unlink")
async def admin_unlink(
    request: Request,
    link_id: Annotated[int, Path(ge=1)],
    session: AsyncSession = Depends(get_session),
) -> Response:
    state = request.app.state
    try:
        return JSONResponse(await links.admin_unlink(
            session, state.settings, getattr(state, "relay_signing_key", None), link_id,
        ))
    except PasskeyError as exc:
        return _refused(exc)

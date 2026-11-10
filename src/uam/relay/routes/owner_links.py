"""The agent's side of linking to an owner (P2d), and the admin unlink.

An agent redeems its owner's code, signs the link body the relay built,
and can read its link's state (for its banners). There is no route for an
agent to unlink itself or to approve anything. 404 while
UAM_OWNERS_ENABLED is off.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Path, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from uam.db.models import Agent
from uam.db.session import get_session
from uam.relay.auth import verify_token_http
from uam.relay.owners import links
from uam.relay.owners.passkeys import PasskeyError
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


@router.get("/link")
async def status(
    request: Request,
    who: dict = Depends(verify_token_http), session: AsyncSession = Depends(get_session),
) -> dict:
    return await links.agent_status(
        session, request.app.state.owner_vault, await _agent(session, who)
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

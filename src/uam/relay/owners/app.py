"""The owner app: owners' API and their page, on its own origin.

The relay serves it only when a request's Host is the owner origin's host,
so the session cookie and the page never share an origin with the relay
API. Every response gets a strict CSP and no-store; every write must come
from the owner origin itself (``Origin`` header), which with the
SameSite=Strict cookie keeps other sites from acting for a signed-in owner.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Depends, FastAPI, HTTPException, Path, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.middleware.cors import CORSMiddleware
from starlette.routing import Host
from starlette.types import ASGIApp, Receive, Scope, Send

from uam.db.crud import owners as crud
from uam.db.session import get_session
from uam.relay.owners import passkeys, service
from uam.relay.owners.crypto import EmailVault, normalise_email
from uam.relay.owners.page import page_router

COOKIE = "__Host-uam_owner"

CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; "
    "connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; "
    "frame-ancestors 'none'"
)
_SECURITY_HEADERS = [
    (b"content-security-policy", CSP.encode()),
    (b"x-content-type-options", b"nosniff"),
    (b"referrer-policy", b"no-referrer"),
    (b"cache-control", b"no-store"),
    (b"x-frame-options", b"DENY"),
    (b"cross-origin-opener-policy", b"same-origin"),
    (b"cross-origin-resource-policy", b"same-origin"),
]
_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def _header(scope: Scope, name: bytes) -> str | None:
    for key, value in scope.get("headers", []):
        if key == name:
            return value.decode("latin-1")
    return None


def request_host(scope: Scope) -> str:
    return (_header(scope, b"host") or "").split(":")[0].lower()


class OwnerGuard:
    """Strict headers on every response; writes only from the owner origin."""

    def __init__(self, app: ASGIApp, origin: str, hsts: bool) -> None:
        self.app = app
        self.origin = origin
        self.headers = list(_SECURITY_HEADERS)
        if hsts:
            self.headers.append((b"strict-transport-security", b"max-age=31536000"))

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message: dict) -> None:
            if message["type"] == "http.response.start":
                names = {k for k, _ in self.headers}
                kept = [(k, v) for k, v in message.get("headers", []) if k.lower() not in names]
                message["headers"] = kept + self.headers
            await send(message)

        if scope["method"] not in _SAFE_METHODS and _header(scope, b"origin") != self.origin:
            response = JSONResponse(
                {"error": "forbidden", "detail": "writes must come from the owner origin"},
                status_code=403,
            )
            await response(scope, receive, send_with_headers)
            return
        await self.app(scope, receive, send_with_headers)


class CORSExceptHost(CORSMiddleware):
    """The relay's CORS, except on the owner host, which gets none at all."""

    def __init__(self, app: ASGIApp, skip_host: str = "", **kwargs) -> None:
        super().__init__(app, **kwargs)
        self.skip_host = skip_host

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if self.skip_host and scope["type"] == "http" and request_host(scope) == self.skip_host:
            await self.app(scope, receive, send)
            return
        await super().__call__(scope, receive, send)


class EmailRequest(BaseModel):
    email: Annotated[str, Field(max_length=320)]


class FinishRequest(EmailRequest):
    code: Annotated[str, Field(pattern=r"^[0-9]{6}$")]


class FinishRegistration(BaseModel):
    attestationObject: Annotated[str, Field(max_length=8192)]
    clientDataJSON: Annotated[str, Field(max_length=4096)]
    # Printable ASCII without '"': labels are quoted in the text owners sign.
    label: Annotated[str, Field(pattern=r"^[\x20\x21\x23-\x7e]{1,64}$")]


class SignEntry(BaseModel):
    credentialId: Annotated[str, Field(max_length=1400)]
    authenticatorData: Annotated[str, Field(max_length=4096)]
    clientDataJSON: Annotated[str, Field(max_length=4096)]
    signature: Annotated[str, Field(max_length=512)]


def _refused(exc: passkeys.PasskeyError) -> JSONResponse:
    return JSONResponse({"error": exc.code, "detail": exc.detail}, status_code=exc.status)


def key_log_router() -> APIRouter:
    """``GET /api/owner/keys/{owner_id}``: an owner's key log, for anyone to
    verify. Served on the owner origin and on the relay origin."""
    router = APIRouter()

    @router.get("/api/owner/keys/{owner_id}")
    async def key_log(
        request: Request,
        owner_id: Annotated[str, Path(pattern=r"^[A-Za-z0-9_-]{22}$")],
        since: Annotated[int, Query(ge=0)] = 0,
        session: AsyncSession = Depends(get_session),
    ) -> dict:
        if not request.app.state.settings.owners_enabled:
            raise HTTPException(status_code=404, detail="Not Found")
        entries = await passkeys.public_log(session, owner_id, since)
        if entries is None:
            raise HTTPException(status_code=404, detail="no such owner")
        return {"owner_id": owner_id, "entries": entries}

    return router


class MeResponse(BaseModel):
    email: str
    status: str
    owner_id: str | None


def _email(raw: str) -> str:
    email = normalise_email(raw)
    if email is None:
        raise HTTPException(status_code=422, detail="not an email address")
    return email


def build_owner_app(settings, parent: FastAPI) -> FastAPI:
    """The owner app for *settings*; *parent* is the relay app (code sink)."""
    app = FastAPI(title="UAM owners", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.settings = settings
    vault = EmailVault(settings.email_pepper, settings.email_key)
    # HSTS only over https; the cookie is always Secure: its __Host- prefix
    # demands it, and browsers keep Secure cookies from http://localhost.
    https = settings.owner_origin.startswith("https://")

    def code_sink() -> service.CodeSink:
        sink = getattr(parent.state, "owner_code_sink", None)
        if sink is not None:
            return sink
        return service.log_sink if settings.owner_codes_to_log else service.drop_sink

    @app.exception_handler(HTTPException)
    async def _http_error(request: Request, exc: HTTPException) -> JSONResponse:
        codes = {401: "unauthorized", 403: "forbidden", 404: "not_found", 422: "validation_error"}
        return JSONResponse(
            {"error": codes.get(exc.status_code, "error"), "detail": exc.detail},
            status_code=exc.status_code,
        )

    @app.exception_handler(RequestValidationError)
    async def _validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        return JSONResponse({"error": "validation_error", "detail": "bad request body"}, status_code=422)

    async def signed_in(
        request: Request, session: AsyncSession = Depends(get_session)
    ) -> service.SignedIn:
        found = await service.current_owner(session, request.cookies.get(COOKIE))
        if found is None:
            raise HTTPException(status_code=401, detail="sign in first")
        return found

    async def start_after_answering(email: str) -> None:
        import uam.db.session as sessions

        try:
            async with sessions._session_factory() as session:
                await service.start_sign_in(session, vault, email, code_sink())
        except Exception:
            service.log.exception("owner sign-in start failed")

    @app.post("/api/owner/sign-in/start", status_code=202)
    async def sign_in_start(body: EmailRequest, background: BackgroundTasks) -> dict:
        # The lookup and writes run after the 202 is sent, so neither the
        # answer nor its timing says whether the email has an account.
        background.add_task(start_after_answering, _email(body.email))
        return {"detail": "If that email has an account, a code is on its way."}

    @app.post("/api/owner/sign-in/finish")
    async def sign_in_finish(
        body: FinishRequest, session: AsyncSession = Depends(get_session)
    ) -> Response:
        token = await service.finish_sign_in(session, vault, _email(body.email), body.code)
        if token is None:
            return JSONResponse(
                {"error": "bad_code", "detail": "That code didn't work. Ask for a new one."},
                status_code=400,
            )
        response = JSONResponse({"status": "signed_in"})
        response.set_cookie(
            COOKIE, token, max_age=int(service.SESSION_MAX.total_seconds()), path="/",
            secure=True, httponly=True, samesite="strict",
        )
        return response

    @app.get("/api/owner/me", response_model=MeResponse)
    async def me(
        who: service.SignedIn = Depends(signed_in), session: AsyncSession = Depends(get_session)
    ) -> MeResponse:
        email = await crud.primary_email(session, who.owner.id)
        return MeResponse(
            email=vault.decrypt(email.email_enc) if email else "",
            status=who.owner.status,
            owner_id=who.owner.owner_id,
        )

    @app.post("/api/owner/passkeys/register/start")
    async def register_start(
        who: service.SignedIn = Depends(signed_in), session: AsyncSession = Depends(get_session)
    ) -> Response:
        email = await crud.primary_email(session, who.owner.id)
        try:
            return JSONResponse(await passkeys.register_options(
                session, settings, owner=who.owner,
                email=vault.decrypt(email.email_enc) if email else "",
                user_handle=vault.user_handle(who.owner.id),
            ))
        except passkeys.PasskeyError as exc:
            return _refused(exc)

    @app.post("/api/owner/passkeys/register/finish")
    async def register_finish(
        body: FinishRegistration,
        who: service.SignedIn = Depends(signed_in),
        session: AsyncSession = Depends(get_session),
    ) -> Response:
        try:
            return JSONResponse(await passkeys.register_finish(
                session, settings, owner=who.owner, attestation_object=body.attestationObject,
                client_data_json=body.clientDataJSON, label=body.label,
            ))
        except passkeys.PasskeyError as exc:
            return _refused(exc)

    @app.post("/api/owner/keys/sign")
    async def sign_entry(
        body: SignEntry,
        who: service.SignedIn = Depends(signed_in),
        session: AsyncSession = Depends(get_session),
    ) -> Response:
        try:
            return JSONResponse(await passkeys.sign_entry(
                session, settings, owner=who.owner, credential_id=body.credentialId,
                authenticator_data=body.authenticatorData,
                client_data_json=body.clientDataJSON, signature=body.signature,
            ))
        except passkeys.PasskeyError as exc:
            return _refused(exc)

    @app.get("/api/owner/passkeys")
    async def list_passkeys(
        who: service.SignedIn = Depends(signed_in), session: AsyncSession = Depends(get_session)
    ) -> dict:
        return {"passkeys": await passkeys.list_passkeys(session, who.owner)}

    app.include_router(key_log_router())
    app.include_router(page_router())

    @app.post("/api/owner/sign-out", status_code=204)
    async def sign_out(request: Request, session: AsyncSession = Depends(get_session)) -> Response:
        found = await service.current_owner(session, request.cookies.get(COOKIE))
        if found is not None:
            await service.sign_out(session, found)
        response = Response(status_code=204)
        response.delete_cookie(COOKIE, path="/", secure=True, httponly=True, samesite="strict")
        return response

    app.add_middleware(OwnerGuard, origin=settings.owner_origin, hsts=https)
    return app


def mount_owner_app(app: FastAPI, settings) -> None:
    """Serve the owner app on the owner host, ahead of every relay route."""
    app.state.owner_vault = EmailVault(settings.email_pepper, settings.email_key)
    owner_app = build_owner_app(settings, app)
    app.router.routes.insert(0, Host(settings.owner_host, app=owner_app))

"""The owner app: owners' API and their page, on its own origin.

The relay serves it only when a request's Host is the owner origin's host,
so the session cookie and the page never share an origin with the relay
API. Every response gets a strict CSP and no-store; every write must come
from the owner origin itself (``Origin`` header), which with the
SameSite=Strict cookie keeps other sites from acting for a signed-in owner.
"""

from __future__ import annotations

from typing import Annotated, Literal

from fastapi import APIRouter, BackgroundTasks, Depends, FastAPI, HTTPException, Path, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from pydantic import (
    AfterValidator,
    BaseModel,
    Field,
    StrictBool,
    StrictInt,
    field_validator,
    model_validator,
)
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.middleware.cors import CORSMiddleware
from starlette.routing import Host
from starlette.types import ASGIApp, Receive, Scope, Send

from uam.db.crud import owners as crud
from uam.db.session import get_session
from uam.relay.owners import (
    contacts,
    fleets,
    freeze,
    links,
    names,
    passkeys,
    policy,
    requests,
    service,
)
from uam.relay.rate_limit import SlidingWindowCounter
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


def _fleet_name(name: str) -> str:
    if any(ord(c) < 32 or ord(c) == 127 for c in name):
        raise ValueError("one line")
    if '"' in name:  # it's quoted in the sentence a passkey signs
        raise ValueError('no "')
    tidy = fleets.tidy(name)
    if not 1 <= len(tidy) <= fleets.MAX_NAME:
        raise ValueError(f"1 to {fleets.MAX_NAME} characters")
    return tidy


FleetName = Annotated[str, Field(max_length=200), AfterValidator(_fleet_name)]


def _distinct(ids: list[int]) -> list[int]:
    if len(set(ids)) != len(ids):
        raise ValueError("each link once")
    return ids


SomeLinks = Annotated[
    list[Annotated[StrictInt, Field(ge=1)]], Field(max_length=policy.MAX_SET),
    AfterValidator(_distinct),
]


class CodeRequest(BaseModel):
    kind: Literal["setup", "link"]
    count: Annotated[StrictInt, Field(ge=1, le=links.MAX_FLEET)] = 1
    fleet: FleetName | None = None


class FleetRequest(BaseModel):
    name: FleetName
    links: SomeLinks = []


class RenameRequest(BaseModel):
    name: FleetName


class MoveRequest(BaseModel):
    links: Annotated[SomeLinks, Field(min_length=1)]
    fleet: Annotated[StrictInt, Field(ge=1)] | None


class ManyPolicyRequest(BaseModel):
    """Several agents (``links``) or one fleet (``fleet``), never both."""

    policy: Literal["open", "contacts"]
    sameOwner: StrictBool
    links: Annotated[SomeLinks, Field(min_length=1)] | None = None
    fleet: Annotated[StrictInt, Field(ge=1)] | None = None
    credentialId: Annotated[str, Field(min_length=1, max_length=1400)] | None = None

    @model_validator(mode="after")
    def _one_of(self) -> "ManyPolicyRequest":
        if (self.links is None) == (self.fleet is None):
            raise ValueError("name some agents or one fleet")
        return self


class SetRequest(BaseModel):
    ids: Annotated[
        list[Annotated[StrictInt, Field(ge=1)]], Field(min_length=1, max_length=links.MAX_FLEET)
    ]

    @field_validator("ids")
    @classmethod
    def _distinct(cls, ids: list[int]) -> list[int]:
        if len(set(ids)) != len(ids):
            raise ValueError("each link once")
        return ids


class PrivateRequest(BaseModel):
    private: StrictBool


class TokenRequest(BaseModel):
    token: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{20,64}$")]


class DeclineRequest(BaseModel):
    block: StrictBool = False


class InviteRequest(BaseModel):
    how: Literal["code", "link"]


_CREDENTIAL = Annotated[str | None, Field(default=None, max_length=1400)]


class EmailInviteRequest(BaseModel):
    email: Annotated[str, Field(max_length=320)]
    credentialId: _CREDENTIAL = None


class InviteKey(BaseModel):
    """What opens an invite: its code, or its link's id and secret."""

    code: Annotated[str | None, Field(default=None, max_length=32)] = None
    link: Annotated[str | None, Field(default=None, pattern=r"^[A-Za-z0-9_-]{16}$")] = None
    secret: Annotated[str | None, Field(default=None, pattern=r"^[A-Za-z0-9_-]{22}$")] = None
    credentialId: _CREDENTIAL = None

    @model_validator(mode="after")
    def _one_way_in(self) -> "InviteKey":
        if (self.code is None) == (self.link is None) or (self.link is None) != (self.secret is None):
            raise ValueError("a code, or a link and its secret")
        return self

    def key(self) -> dict[str, str]:
        return {"code": self.code} if self.code is not None else {
            "link": self.link, "secret": self.secret,
        }


class CredentialChoice(BaseModel):
    credentialId: _CREDENTIAL = None


class PolicyRequest(BaseModel):
    policy: Literal["open", "contacts"]
    sameOwner: StrictBool
    credentialId: _CREDENTIAL = None


class KeepRequest(BaseModel):
    contacts: Annotated[
        list[Annotated[str, Field(min_length=3, max_length=320)]],
        Field(min_length=1, max_length=policy.MAX_KEEP),
    ]
    credentialId: _CREDENTIAL = None


LinkId = Annotated[int, Path(ge=1)]
FleetId = Annotated[int, Path(ge=1)]
OwnerIdPath = Annotated[str, Path(pattern=r"^[A-Za-z0-9_-]{22}$")]


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
    #: Set when this session came from an agent's request email.
    request: int | None = None
    #: Set when this session came from a reservation email.
    reservation: int | None = None


#: Sign-ups one client address can start in an hour.
SIGNUPS_PER_HOUR = 10


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
        mailer = getattr(parent.state, "owner_mailer", None)
        if mailer is not None:
            return mailer.code
        return service.log_sink if settings.owner_codes_to_log else service.drop_sink

    def contact_sink() -> contacts.ContactNotice:
        sink = getattr(parent.state, "owner_contact_sink", None)
        if sink is not None:
            return sink
        mailer = getattr(parent.state, "owner_mailer", None)
        return mailer.notice if mailer is not None else contacts.log_notice

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

    async def any_session(
        request: Request, session: AsyncSession = Depends(get_session)
    ) -> service.SignedIn:
        """A signed-in session, or one opened from an agent's request email."""
        found = await service.current_owner(session, request.cookies.get(COOKIE))
        if found is None:
            raise HTTPException(status_code=401, detail="sign in first")
        return found

    async def signed_in(who: service.SignedIn = Depends(any_session)) -> service.SignedIn:
        """A full sign-in: an email link's session can't see the account."""
        if who.scoped:
            raise HTTPException(status_code=401, detail="sign in first")
        return who

    async def first_passkey(who: service.SignedIn = Depends(any_session)) -> service.SignedIn:
        """A full sign-in, or an email link's session making the account's
        first passkey (an account with one uses it instead)."""
        if who.scoped and who.owner.owner_id is not None:
            raise HTTPException(status_code=401, detail="sign in first")
        return who

    async def not_a_request(who: service.SignedIn = Depends(any_session)) -> service.SignedIn:
        """A full sign-in, or a reservation email's session."""
        if who.request_id is not None:
            raise HTTPException(status_code=401, detail="sign in first")
        return who

    async def not_a_reservation(who: service.SignedIn = Depends(any_session)) -> service.SignedIn:
        """A full sign-in, or a request email's session."""
        if who.reservation_id is not None:
            raise HTTPException(status_code=401, detail="sign in first")
        return who

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

    # Sign-ups per client address, checked before answering: a count says
    # nothing about any email.
    signup_limiter = SlidingWindowCounter(limit=SIGNUPS_PER_HOUR, window_seconds=3600.0)

    async def sign_up_after_answering(email: str) -> None:
        import uam.db.session as sessions

        try:
            async with sessions._session_factory() as session:
                await service.sign_up(session, vault, email, code_sink())
        except Exception:
            service.log.exception("owner sign-up failed")

    @app.post("/api/owner/sign-up", status_code=202)
    async def sign_up(
        body: EmailRequest, request: Request, background: BackgroundTasks
    ) -> Response:
        email = _email(body.email)
        if not await signup_limiter.check(request.client.host if request.client else "unknown"):
            return JSONResponse(
                {"error": "too_many", "detail": "Too many sign-ups from here. Try again later."},
                status_code=429,
            )
        # Like sign-in: the work runs after the 202, so neither the answer
        # nor its timing says whether the email already had an account.
        background.add_task(sign_up_after_answering, email)
        return JSONResponse(
            {"detail": "Check your email for a code."}, status_code=202
        )

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
        who: service.SignedIn = Depends(any_session), session: AsyncSession = Depends(get_session)
    ) -> MeResponse:
        email = await crud.primary_email(session, who.owner.id)
        return MeResponse(
            email=vault.decrypt(email.email_enc) if email else "",
            status=who.owner.status,
            owner_id=who.owner.owner_id,
            request=who.request_id,
            reservation=who.reservation_id,
        )

    @app.post("/api/owner/passkeys/register/start")
    async def register_start(
        who: service.SignedIn = Depends(first_passkey), session: AsyncSession = Depends(get_session)
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
        who: service.SignedIn = Depends(first_passkey),
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
        who: service.SignedIn = Depends(first_passkey),
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

    @app.post("/api/owner/codes")
    async def make_code(
        body: CodeRequest,
        who: service.SignedIn = Depends(signed_in),
        session: AsyncSession = Depends(get_session),
    ) -> Response:
        try:
            return JSONResponse(
                await links.make_code(
                    session, vault, who.owner, body.kind, body.count, fleet=body.fleet
                )
            )
        except passkeys.PasskeyError as exc:
            return _refused(exc)

    @app.get("/api/owner/links")
    async def list_links(
        who: service.SignedIn = Depends(signed_in), session: AsyncSession = Depends(get_session)
    ) -> dict:
        return {"links": await links.list_links(session, who.owner)}

    @app.post("/api/owner/links/{link_id}/approve/start")
    async def approve_start(
        link_id: LinkId,
        who: service.SignedIn = Depends(signed_in),
        session: AsyncSession = Depends(get_session),
    ) -> Response:
        try:
            return JSONResponse(await links.approve_start(session, settings, who.owner, link_id))
        except passkeys.PasskeyError as exc:
            return _refused(exc)

    @app.post("/api/owner/links/{link_id}/approve")
    async def approve(
        link_id: LinkId,
        body: SignEntry,
        who: service.SignedIn = Depends(signed_in),
        session: AsyncSession = Depends(get_session),
    ) -> Response:
        try:
            approved = await links.approve(session, settings, who.owner, link_id, body.model_dump())
        except passkeys.PasskeyError as exc:
            return _refused(exc)
        await requests.settle_approved(session, [approved["id"]])
        return JSONResponse(approved)

    async def only_links(session: AsyncSession, who: service.SignedIn) -> set[int] | None:
        """The links a request email's session may approve: its request's."""
        if who.request_id is None:
            return None
        link_id = await requests.link_of(session, who.request_id)
        return {link_id} if link_id else set()

    _NOT_YOURS = passkeys.PasskeyError(
        403, "not_yours", "This session can only approve its own request."
    )

    @app.post("/api/owner/link-sets/approve/start")
    async def approve_set_start(
        body: SetRequest,
        who: service.SignedIn = Depends(not_a_reservation),
        session: AsyncSession = Depends(get_session),
    ) -> Response:
        only = await only_links(session, who)
        if only is not None and not set(body.ids) <= only:
            return _refused(_NOT_YOURS)
        try:
            return JSONResponse(
                await links.approve_set_start(session, settings, who.owner, body.ids)
            )
        except passkeys.PasskeyError as exc:
            return _refused(exc)

    @app.post("/api/owner/link-sets/approve")
    async def approve_set(
        body: SignEntry,
        who: service.SignedIn = Depends(not_a_reservation),
        session: AsyncSession = Depends(get_session),
    ) -> Response:
        try:
            approved = await links.approve_set(
                session, settings, who.owner, body.model_dump(),
                only=await only_links(session, who),
            )
        except passkeys.PasskeyError as exc:
            return _refused(exc)
        await requests.settle_approved(session, [x["id"] for x in approved["links"]])
        return JSONResponse(approved)

    # --- names held for an account (P2s-2) -------------------------------------

    @app.post("/api/owner/reservations/open")
    async def open_reservation(
        body: TokenRequest, request: Request, session: AsyncSession = Depends(get_session)
    ) -> Response:
        """The page calls this with the token from the email link's fragment."""
        try:
            owner, row = await names.open_reservation(session, vault, body.token)
        except passkeys.PasskeyError as exc:
            return _refused(exc)
        response = JSONResponse({"reservation": names.view(row)})
        current = await service.current_owner(session, request.cookies.get(COOKIE))
        if current is not None and current.owner.id == owner.id and not current.scoped:
            return response  # already signed in to this account: keep that session
        token = await names.scoped_session(session, owner, row)
        response.set_cookie(
            COOKIE, token, max_age=int(service.SESSION_MAX.total_seconds()), path="/",
            secure=True, httponly=True, samesite="strict",
        )
        return response

    @app.get("/api/owner/reservations")
    async def list_reservations(
        who: service.SignedIn = Depends(not_a_request), session: AsyncSession = Depends(get_session)
    ) -> dict:
        return {"reservations": await names.list_held(session, who.owner, who.reservation_id)}

    @app.post("/api/owner/reservations/{reservation_id}/code")
    async def reservation_code(
        reservation_id: LinkId,
        who: service.SignedIn = Depends(not_a_request),
        session: AsyncSession = Depends(get_session),
    ) -> Response:
        try:
            return JSONResponse(await names.make_code(
                session, vault, who.owner, reservation_id, who.reservation_id))
        except passkeys.PasskeyError as exc:
            return _refused(exc)

    # --- agents asking for an owner by email (P2s-3) ---------------------------

    @app.post("/api/owner/requests/open")
    async def open_request(
        body: TokenRequest, request: Request, session: AsyncSession = Depends(get_session)
    ) -> Response:
        """The page calls this with the token from the email link's fragment."""
        try:
            owner, row = await requests.open_request(session, vault, body.token)
        except passkeys.PasskeyError as exc:
            return _refused(exc)
        shown = await requests.view(session, row, service.utcnow())
        response = JSONResponse({"request": shown})
        current = await service.current_owner(session, request.cookies.get(COOKIE))
        if current is not None and current.owner.id == owner.id and not current.scoped:
            return response  # already signed in to this account: keep that session
        token = await requests.scoped_session(session, owner, row)
        response.set_cookie(
            COOKIE, token, max_age=int(service.SESSION_MAX.total_seconds()), path="/",
            secure=True, httponly=True, samesite="strict",
        )
        return response

    @app.post("/api/owner/requests/never")
    async def never_email(body: TokenRequest, session: AsyncSession = Depends(get_session)) -> Response:
        try:
            if not await names.never(session, body.token):
                await requests.never(session, body.token)
        except passkeys.PasskeyError as exc:
            return _refused(exc)
        return JSONResponse({"detail": "We won't email you about agents or reserved names again."})

    # --- a frozen account's keep link (DEC-010) --------------------------------

    @app.post("/api/owner/freeze/keep")
    async def keep_account(body: TokenRequest, session: AsyncSession = Depends(get_session)) -> Response:
        """The page calls this with the token from the frozen-account email."""
        try:
            return JSONResponse(await freeze.keep(session, body.token))
        except passkeys.PasskeyError as exc:
            return _refused(exc)

    @app.get("/api/owner/requests")
    async def list_requests(
        who: service.SignedIn = Depends(not_a_reservation), session: AsyncSession = Depends(get_session)
    ) -> Response:
        try:
            return JSONResponse({"requests": await requests.list_requests(
                session, who.owner, who.request_id)})
        except passkeys.PasskeyError as exc:
            return _refused(exc)

    @app.get("/api/owner/requests/{request_id}")
    async def get_request(
        request_id: LinkId,
        who: service.SignedIn = Depends(not_a_reservation),
        session: AsyncSession = Depends(get_session),
    ) -> Response:
        try:
            return JSONResponse(await requests.get_request(
                session, who.owner, request_id, who.request_id))
        except passkeys.PasskeyError as exc:
            return _refused(exc)

    @app.post("/api/owner/requests/{request_id}/accept")
    async def accept_request(
        request_id: LinkId,
        who: service.SignedIn = Depends(not_a_reservation),
        session: AsyncSession = Depends(get_session),
    ) -> Response:
        try:
            return JSONResponse(await requests.accept(
                session, settings, who.owner, request_id, who.request_id))
        except passkeys.PasskeyError as exc:
            return _refused(exc)

    @app.post("/api/owner/requests/{request_id}/decline")
    async def decline_request(
        request_id: LinkId,
        body: DeclineRequest,
        who: service.SignedIn = Depends(not_a_reservation),
        session: AsyncSession = Depends(get_session),
    ) -> Response:
        try:
            return JSONResponse(await requests.decline(
                session, who.owner, request_id, body.block, who.request_id))
        except passkeys.PasskeyError as exc:
            return _refused(exc)

    @app.post("/api/owner/links/{link_id}/cancel")
    async def cancel(
        link_id: LinkId,
        who: service.SignedIn = Depends(signed_in),
        session: AsyncSession = Depends(get_session),
    ) -> Response:
        try:
            return JSONResponse(await links.cancel(session, who.owner, link_id))
        except passkeys.PasskeyError as exc:
            return _refused(exc)

    @app.post("/api/owner/links/{link_id}/unlink/start")
    async def unlink_start(
        link_id: LinkId,
        who: service.SignedIn = Depends(signed_in),
        session: AsyncSession = Depends(get_session),
    ) -> Response:
        try:
            return JSONResponse(await links.unlink_start(session, settings, who.owner, link_id))
        except passkeys.PasskeyError as exc:
            return _refused(exc)

    @app.post("/api/owner/links/{link_id}/unlink")
    async def unlink(
        link_id: LinkId,
        body: SignEntry,
        who: service.SignedIn = Depends(signed_in),
        session: AsyncSession = Depends(get_session),
    ) -> Response:
        try:
            return JSONResponse(
                await links.unlink(session, settings, who.owner, link_id, body.model_dump())
            )
        except passkeys.PasskeyError as exc:
            return _refused(exc)

    @app.post("/api/owner/links/{link_id}/private")
    async def make_private(
        link_id: LinkId,
        body: PrivateRequest,
        who: service.SignedIn = Depends(signed_in),
        session: AsyncSession = Depends(get_session),
    ) -> Response:
        try:
            return JSONResponse(await links.make_private(session, who.owner, link_id, body.private))
        except passkeys.PasskeyError as exc:
            return _refused(exc)

    # --- owners connect (P2e) ----------------------------------------------------

    @app.post("/api/owner/invites")
    async def make_invite(
        body: InviteRequest,
        who: service.SignedIn = Depends(signed_in),
        session: AsyncSession = Depends(get_session),
    ) -> Response:
        try:
            return JSONResponse(
                await contacts.make_invite(session, settings, vault, who.owner, body.how)
            )
        except passkeys.PasskeyError as exc:
            return _refused(exc)

    @app.get("/api/owner/invites")
    async def list_invites(
        who: service.SignedIn = Depends(signed_in), session: AsyncSession = Depends(get_session)
    ) -> dict:
        return {"invites": await contacts.list_invites(session, vault, who.owner)}

    @app.post("/api/owner/invites/email/start")
    async def email_invite_start(
        body: EmailInviteRequest,
        who: service.SignedIn = Depends(signed_in),
        session: AsyncSession = Depends(get_session),
    ) -> Response:
        try:
            return JSONResponse(await contacts.email_start(
                session, settings, vault, who.owner, _email(body.email), body.credentialId
            ))
        except passkeys.PasskeyError as exc:
            return _refused(exc)

    @app.post("/api/owner/invites/email")
    async def email_invite(
        body: SignEntry,
        who: service.SignedIn = Depends(signed_in),
        session: AsyncSession = Depends(get_session),
    ) -> Response:
        try:
            return JSONResponse(
                await contacts.email_finish(session, settings, vault, who.owner, body.model_dump())
            )
        except passkeys.PasskeyError as exc:
            return _refused(exc)

    @app.post("/api/owner/invites/find")
    async def find_invite(
        body: InviteKey,
        who: service.SignedIn = Depends(signed_in),
        session: AsyncSession = Depends(get_session),
    ) -> Response:
        try:
            return JSONResponse(
                await contacts.find(session, vault, who.owner, body.key(), contact_sink())
            )
        except passkeys.PasskeyError as exc:
            return _refused(exc)

    @app.post("/api/owner/invites/redeem/start")
    async def redeem_start(
        body: InviteKey,
        who: service.SignedIn = Depends(signed_in),
        session: AsyncSession = Depends(get_session),
    ) -> Response:
        try:
            return JSONResponse(await contacts.redeem_start(
                session, settings, vault, who.owner, body.key(), body.credentialId, contact_sink()
            ))
        except passkeys.PasskeyError as exc:
            return _refused(exc)

    @app.post("/api/owner/invites/redeem")
    async def redeem(
        body: SignEntry,
        who: service.SignedIn = Depends(signed_in),
        session: AsyncSession = Depends(get_session),
    ) -> Response:
        try:
            return JSONResponse(await contacts.redeem(
                session, settings, vault, who.owner, body.model_dump(), contact_sink()
            ))
        except passkeys.PasskeyError as exc:
            return _refused(exc)

    @app.post("/api/owner/invites/{invite_id}/cancel")
    async def cancel_invite(
        invite_id: LinkId,
        who: service.SignedIn = Depends(signed_in),
        session: AsyncSession = Depends(get_session),
    ) -> Response:
        try:
            return JSONResponse(await contacts.cancel(session, vault, who.owner, invite_id))
        except passkeys.PasskeyError as exc:
            return _refused(exc)

    @app.post("/api/owner/invites/{invite_id}/confirm/start")
    async def confirm_start(
        invite_id: LinkId,
        body: CredentialChoice | None = None,
        who: service.SignedIn = Depends(signed_in),
        session: AsyncSession = Depends(get_session),
    ) -> Response:
        try:
            return JSONResponse(await contacts.confirm_start(
                session, settings, vault, who.owner, invite_id,
                body.credentialId if body else None,
            ))
        except passkeys.PasskeyError as exc:
            return _refused(exc)

    @app.post("/api/owner/invites/{invite_id}/confirm")
    async def confirm(
        invite_id: LinkId,
        body: SignEntry,
        who: service.SignedIn = Depends(signed_in),
        session: AsyncSession = Depends(get_session),
    ) -> Response:
        try:
            return JSONResponse(await contacts.confirm(
                session, settings, vault, who.owner, invite_id, body.model_dump(), contact_sink()
            ))
        except passkeys.PasskeyError as exc:
            return _refused(exc)

    @app.get("/api/owner/links/{link_id}/policy")
    async def read_policy(
        link_id: LinkId,
        who: service.SignedIn = Depends(signed_in),
        session: AsyncSession = Depends(get_session),
    ) -> Response:
        try:
            return JSONResponse(await policy.read(session, who.owner, link_id))
        except passkeys.PasskeyError as exc:
            return _refused(exc)

    @app.post("/api/owner/links/{link_id}/policy")
    async def narrow_policy(
        link_id: LinkId,
        body: PolicyRequest,
        who: service.SignedIn = Depends(signed_in),
        session: AsyncSession = Depends(get_session),
    ) -> Response:
        try:
            return JSONResponse(
                await policy.narrow(session, who.owner, link_id, body.policy, body.sameOwner)
            )
        except passkeys.PasskeyError as exc:
            return _refused(exc)

    @app.post("/api/owner/links/{link_id}/policy/approve/start")
    async def widen_policy_start(
        link_id: LinkId,
        body: PolicyRequest,
        who: service.SignedIn = Depends(signed_in),
        session: AsyncSession = Depends(get_session),
    ) -> Response:
        try:
            return JSONResponse(await policy.widen_start(
                session, settings, who.owner, link_id, body.policy, body.sameOwner,
                body.credentialId,
            ))
        except passkeys.PasskeyError as exc:
            return _refused(exc)

    @app.post("/api/owner/links/{link_id}/policy/approve")
    async def widen_policy(
        link_id: LinkId,
        body: SignEntry,
        who: service.SignedIn = Depends(signed_in),
        session: AsyncSession = Depends(get_session),
    ) -> Response:
        try:
            return JSONResponse(
                await policy.widen(session, settings, who.owner, link_id, body.model_dump())
            )
        except passkeys.PasskeyError as exc:
            return _refused(exc)

    # --- fleets, and several agents at once (P2e-1b) ---------------------------

    @app.get("/api/owner/fleets")
    async def list_fleets(
        who: service.SignedIn = Depends(signed_in), session: AsyncSession = Depends(get_session)
    ) -> dict:
        return await fleets.list_fleets(session, who.owner)

    @app.post("/api/owner/fleets")
    async def make_fleet(
        body: FleetRequest,
        who: service.SignedIn = Depends(signed_in),
        session: AsyncSession = Depends(get_session),
    ) -> Response:
        try:
            return JSONResponse(await fleets.make(session, who.owner, body.name, body.links))
        except passkeys.PasskeyError as exc:
            return _refused(exc)

    @app.post("/api/owner/fleets/move")
    async def move_to_fleet(
        body: MoveRequest,
        who: service.SignedIn = Depends(signed_in),
        session: AsyncSession = Depends(get_session),
    ) -> Response:
        try:
            return JSONResponse(await fleets.move(session, who.owner, body.links, body.fleet))
        except passkeys.PasskeyError as exc:
            return _refused(exc)

    @app.post("/api/owner/fleets/{fleet_id}/rename")
    async def rename_fleet(
        fleet_id: FleetId,
        body: RenameRequest,
        who: service.SignedIn = Depends(signed_in),
        session: AsyncSession = Depends(get_session),
    ) -> Response:
        try:
            return JSONResponse(await fleets.rename(session, who.owner, fleet_id, body.name))
        except passkeys.PasskeyError as exc:
            return _refused(exc)

    @app.post("/api/owner/fleets/{fleet_id}/ungroup")
    async def ungroup_fleet(
        fleet_id: FleetId,
        who: service.SignedIn = Depends(signed_in),
        session: AsyncSession = Depends(get_session),
    ) -> Response:
        try:
            return JSONResponse(await fleets.ungroup(session, who.owner, fleet_id))
        except passkeys.PasskeyError as exc:
            return _refused(exc)

    @app.post("/api/owner/policy")
    async def narrow_many(
        body: ManyPolicyRequest,
        who: service.SignedIn = Depends(signed_in),
        session: AsyncSession = Depends(get_session),
    ) -> Response:
        try:
            return JSONResponse(await policy.narrow_many(
                session, who.owner, body.links, body.fleet, body.policy, body.sameOwner,
            ))
        except passkeys.PasskeyError as exc:
            return _refused(exc)

    @app.post("/api/owner/policy/approve/start")
    async def widen_many_start(
        body: ManyPolicyRequest,
        who: service.SignedIn = Depends(signed_in),
        session: AsyncSession = Depends(get_session),
    ) -> Response:
        try:
            return JSONResponse(await policy.widen_many_start(
                session, settings, who.owner, body.links, body.fleet, body.policy,
                body.sameOwner, body.credentialId,
            ))
        except passkeys.PasskeyError as exc:
            return _refused(exc)

    @app.post("/api/owner/policy/approve")
    async def widen_many(
        body: SignEntry,
        who: service.SignedIn = Depends(signed_in),
        session: AsyncSession = Depends(get_session),
    ) -> Response:
        try:
            return JSONResponse(
                await policy.widen_many(session, settings, who.owner, body.model_dump())
            )
        except passkeys.PasskeyError as exc:
            return _refused(exc)

    @app.post("/api/owner/links/{link_id}/keep/start")
    async def keep_start(
        link_id: LinkId,
        body: KeepRequest,
        who: service.SignedIn = Depends(signed_in),
        session: AsyncSession = Depends(get_session),
    ) -> Response:
        try:
            return JSONResponse(await policy.keep_start(
                session, settings, who.owner, link_id, body.contacts, body.credentialId
            ))
        except passkeys.PasskeyError as exc:
            return _refused(exc)

    @app.post("/api/owner/links/{link_id}/keep")
    async def keep(
        link_id: LinkId,
        body: SignEntry,
        who: service.SignedIn = Depends(signed_in),
        session: AsyncSession = Depends(get_session),
    ) -> Response:
        try:
            return JSONResponse(
                await policy.keep(session, settings, who.owner, link_id, body.model_dump())
            )
        except passkeys.PasskeyError as exc:
            return _refused(exc)

    @app.get("/api/owner/contacts")
    async def list_contacts(
        who: service.SignedIn = Depends(signed_in), session: AsyncSession = Depends(get_session)
    ) -> dict:
        return {"contacts": await contacts.list_contacts(session, vault, who.owner)}

    @app.post("/api/owner/contacts/{owner_id}/remove")
    async def remove_contact(
        owner_id: OwnerIdPath,
        who: service.SignedIn = Depends(signed_in),
        session: AsyncSession = Depends(get_session),
    ) -> Response:
        try:
            return JSONResponse(await contacts.remove(session, vault, who.owner, owner_id))
        except passkeys.PasskeyError as exc:
            return _refused(exc)

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

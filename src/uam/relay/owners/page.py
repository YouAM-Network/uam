"""The owner page: ``/`` on the owner origin, and its pinned assets.

The HTML names each asset by a hash of its content and pins it with an SRI
hash, so the browser runs exactly the script this relay shipped. Only those
names are served; nothing is read from disk after start-up.
"""

from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass
from importlib import resources

from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse, Response

_ASSETS = {
    "tokens.css": "text/css; charset=utf-8",
    "owner.css": "text/css; charset=utf-8",
    "owner.js": "text/javascript; charset=utf-8",
}

#: contacts.invite_id: the first 16 characters of the invite's hash.
_INVITE_ID = re.compile(r"[A-Za-z0-9_-]{16}")


@dataclass(frozen=True)
class Asset:
    url: str
    integrity: str
    data: bytes
    media_type: str


def _load(name: str) -> bytes:
    return resources.files("uam.relay.owners").joinpath("static", name).read_bytes()


def _asset(name: str, media_type: str) -> Asset:
    data = _load(name)
    stem, ext = name.rsplit(".", 1)
    url = f"/static/{stem}-{hashlib.sha256(data).hexdigest()[:12]}.{ext}"
    integrity = "sha384-" + base64.b64encode(hashlib.sha384(data).digest()).decode()
    return Asset(url, integrity, data, media_type)


def _fill(template: str, assets: dict[str, Asset]) -> str:
    html = _load(template).decode()
    for name, asset in assets.items():
        html = html.replace("{{" + name + "}}", asset.url)
        html = html.replace("{{" + name + ":integrity}}", asset.integrity)
    if "{{" in html:
        raise RuntimeError(f"{template} names an asset that isn't served")
    return html


def page_router() -> APIRouter:
    assets = {name: _asset(name, kind) for name, kind in _ASSETS.items()}
    html = _fill("index.html", assets)
    # The beta privacy notice (P2g-2): plain HTML on the same stylesheets.
    privacy_html = _fill("privacy.html", assets)
    by_url = {asset.url: asset for asset in assets.values()}
    router = APIRouter()

    @router.get("/", response_class=HTMLResponse, include_in_schema=False)
    async def index() -> HTMLResponse:
        return HTMLResponse(html)

    @router.get("/privacy", response_class=HTMLResponse, include_in_schema=False)
    async def privacy() -> HTMLResponse:
        return HTMLResponse(privacy_html)

    # An invite link (/i/<id>#<secret>, P2e): the same page, which reads the
    # id from the path and the secret from the fragment the server never sees.
    @router.get("/i/{invite_id}", response_class=HTMLResponse, include_in_schema=False)
    async def invite(invite_id: str) -> HTMLResponse:
        if not _INVITE_ID.fullmatch(invite_id):
            raise HTTPException(status_code=404, detail="Not Found")
        return HTMLResponse(html)

    @router.get("/static/{name}", include_in_schema=False)
    async def static(name: str) -> Response:
        asset = by_url.get(f"/static/{name}")
        if asset is None:
            raise HTTPException(status_code=404, detail="Not Found")
        return Response(asset.data, media_type=asset.media_type)

    return router

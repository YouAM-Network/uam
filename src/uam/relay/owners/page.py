"""The owner page: ``/`` on the owner origin, and its pinned assets.

The HTML names each asset by a hash of its content and pins it with an SRI
hash, so the browser runs exactly the script this relay shipped. Only those
names are served; nothing is read from disk after start-up.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from importlib import resources

from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse, Response

_ASSETS = {
    "tokens.css": "text/css; charset=utf-8",
    "owner.css": "text/css; charset=utf-8",
    "owner.js": "text/javascript; charset=utf-8",
}


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


def page_router() -> APIRouter:
    assets = {name: _asset(name, kind) for name, kind in _ASSETS.items()}
    html = _load("index.html").decode()
    for name, asset in assets.items():
        html = html.replace("{{" + name + "}}", asset.url)
        html = html.replace("{{" + name + ":integrity}}", asset.integrity)
    if "{{" in html:
        raise RuntimeError("owner page template names an asset that isn't served")
    by_url = {asset.url: asset for asset in assets.values()}
    router = APIRouter()

    @router.get("/", response_class=HTMLResponse, include_in_schema=False)
    async def index() -> HTMLResponse:
        return HTMLResponse(html)

    @router.get("/static/{name}", include_in_schema=False)
    async def static(name: str) -> Response:
        asset = by_url.get(f"/static/{name}")
        if asset is None:
            raise HTTPException(status_code=404, detail="Not Found")
        return Response(asset.data, media_type=asset.media_type)

    return router

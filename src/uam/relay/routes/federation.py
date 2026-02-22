"""POST /federation/deliver -- federation stub endpoint (RELAY-07).

Returns 501 Not Implemented until federation support is built.
No authentication required (it's a public stub).
"""

from __future__ import annotations

from fastapi import APIRouter
from starlette.responses import JSONResponse

router = APIRouter()


@router.post("/federation/deliver")
async def federation_deliver() -> JSONResponse:
    """Stub endpoint for relay-to-relay federation."""
    return JSONResponse(
        status_code=501,
        content={"status": "not_implemented", "detail": "Federation is not yet supported"},
    )

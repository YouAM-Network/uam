"""HTTP transport via httpx with connection pooling (SDK-09)."""

from __future__ import annotations

from typing import Any, Awaitable, Callable

import httpx

from uam.sdk.transport.base import TransportBase


class HTTPTransport(TransportBase):
    """Stateless HTTP transport using httpx AsyncClient.

    Sends envelopes via ``POST /api/v1/send`` and retrieves inbox
    via ``GET /api/v1/inbox/{address}``.

    A single ``httpx.AsyncClient`` is created in ``connect()`` and
    reused for all requests (connection pooling).  Call ``disconnect()``
    to close it.
    """

    def __init__(self, relay_url: str, token: str, address: str) -> None:
        self._relay_url = relay_url
        self._token = token
        self._address = address
        self._client: httpx.AsyncClient | None = None

    async def connect(self) -> None:
        """Create the shared httpx AsyncClient."""
        self._client = httpx.AsyncClient(
            base_url=self._relay_url,
            headers={"Authorization": f"Bearer {self._token}"},
            timeout=30.0,
        )

    async def disconnect(self) -> None:
        """Close the httpx client."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def send(self, envelope: dict[str, Any]) -> None:
        """POST an envelope to the relay.

        Raises ``httpx.HTTPStatusError`` on 4xx/5xx.
        """
        if self._client is None:
            raise RuntimeError("HTTPTransport not connected. Call connect() first.")
        resp = await self._client.post("/api/v1/send", json={"envelope": envelope})
        resp.raise_for_status()

    async def receive(self, limit: int = 50) -> list[dict[str, Any]]:
        """GET pending messages from the relay inbox.

        Returns a list of envelope dicts.
        """
        if self._client is None:
            raise RuntimeError("HTTPTransport not connected. Call connect() first.")
        resp = await self._client.get(
            f"/api/v1/inbox/{self._address}",
            params={"limit": limit},
        )
        resp.raise_for_status()
        data = resp.json()
        return data.get("messages", [])

    async def listen(self, callback: Callable[[dict], Awaitable[None]]) -> None:
        """Not supported for HTTP transport.

        Use ``receive()`` for polling instead.
        """
        raise NotImplementedError(
            "HTTP transport does not support real-time listening. "
            "Use receive() for polling or switch to WebSocket transport."
        )

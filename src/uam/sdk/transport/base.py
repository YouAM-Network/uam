"""Abstract transport interface for relay communication."""

from __future__ import annotations

import abc
from typing import Any, Awaitable, Callable


class TransportBase(abc.ABC):
    """Abstract transport layer for relay communication.

    Two implementations:
    - ``HTTPTransport``: stateless polling via REST API
    - ``WebSocketTransport``: persistent real-time connection
    """

    @abc.abstractmethod
    async def connect(self) -> None:
        """Establish connection to the relay."""

    @abc.abstractmethod
    async def disconnect(self) -> None:
        """Close the connection."""

    @abc.abstractmethod
    async def send(self, envelope: dict[str, Any]) -> None:
        """Send a message envelope to the relay."""

    @abc.abstractmethod
    async def receive(self, limit: int = 50) -> list[dict[str, Any]]:
        """Retrieve pending messages from the relay."""

    @abc.abstractmethod
    async def listen(self, callback: Callable[[dict], Awaitable[None]]) -> None:
        """Start listening for real-time messages.

        For WebSocket: registers a callback for push delivery.
        For HTTP: not supported (raises NotImplementedError).
        """

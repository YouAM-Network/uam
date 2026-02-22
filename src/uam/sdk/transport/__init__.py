"""UAM SDK transport layer."""

from uam.sdk.transport.base import TransportBase
from uam.sdk.transport.http import HTTPTransport
from uam.sdk.transport.websocket import WebSocketTransport


def create_transport(
    config,
    token: str,
    address: str,
    on_message=None,
) -> TransportBase:
    """Factory to create the appropriate transport based on config."""
    if config.transport_type == "http":
        return HTTPTransport(
            relay_url=config.relay_url,
            token=token,
            address=address,
        )
    else:
        return WebSocketTransport(
            ws_url=config.relay_ws_url,
            token=token,
            on_message=on_message,
        )


__all__ = [
    "TransportBase",
    "HTTPTransport",
    "WebSocketTransport",
    "create_transport",
]

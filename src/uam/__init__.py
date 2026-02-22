"""UAM -- Universal Agent Messaging.

Top-level convenience re-exports::

    from uam import Agent, ReceivedMessage
    from uam.protocol import MessageType, create_envelope  # protocol functions
"""

__version__ = "0.1.0"

try:
    from uam.sdk.agent import Agent
    from uam.sdk.message import ReceivedMessage

    __all__ = ["__version__", "Agent", "ReceivedMessage"]
except ImportError:
    # SDK dependencies (httpx, websockets) not installed -- protocol-only usage
    __all__ = ["__version__"]

"""Agent class -- the primary SDK interface (SDK-01).

Provides send(), inbox(), handshake flow, contact management,
trust policies, approve/deny/block/unblock, and sync wrappers
for the complete UAM messaging experience.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time

import httpx

from uam.protocol import (
    MessageType,
    UAMError,
    SignatureVerificationError,
    DecryptionError,
    create_envelope,
    verify_envelope,
    decrypt_payload,
    to_wire_dict,
    from_wire_dict,
    serialize_verify_key,
    deserialize_verify_key,
    create_contact_card,
    contact_card_to_dict,
    contact_card_from_dict,
    verify_contact_card,
)
from uam.sdk.config import SDKConfig
from uam.sdk.key_manager import KeyManager
from uam.sdk.message import ReceivedMessage
from uam.sdk.contact_book import ContactBook
from uam.sdk.handshake import HandshakeManager
from uam.sdk.resolver import AddressResolver, SmartResolver
from uam.sdk.transport import create_transport
from uam.sdk._sync import _run_sync

logger = logging.getLogger(__name__)


class Agent:
    """A UAM agent -- the primary SDK interface.

    Usage::

        agent = Agent("myagent")
        await agent.connect()
        msg_id = await agent.send("other::domain", "Hello!")
        messages = await agent.inbox()

    Async context manager::

        async with Agent("myagent") as agent:
            print(agent.address)

    Sync usage::

        agent = Agent("myagent")
        agent.connect_sync()
        agent.send_sync("other::domain", "Hello!")
        agent.close_sync()
    """

    def __init__(
        self,
        name: str,
        *,
        relay: str | None = None,
        domain: str | None = None,
        key_dir: str | None = None,
        auto_register: bool = True,
        display_name: str | None = None,
        transport: str = "websocket",
        trust_policy: str = "auto-accept",
    ) -> None:
        """Create an Agent.  No I/O happens here -- call ``connect()`` to initialize."""
        self._config = SDKConfig(
            name=name,
            relay_url=relay,
            relay_domain=domain or "",
            key_dir=key_dir,
            display_name=display_name or name,
            transport_type=transport,
            trust_policy=trust_policy,
        )
        self._key_manager = KeyManager(self._config.key_dir)
        self._resolver: AddressResolver = SmartResolver(self._config.relay_domain)
        self._transport = None  # Lazy-initialized on connect()
        self._address: str | None = None
        self._token: str | None = None
        self._connected: bool = False
        self._auto_register = auto_register

        # Contact management
        self._contact_book = ContactBook(self._config.data_dir)
        self._handshake = HandshakeManager(
            self._contact_book, self._config.trust_policy
        )

    # -- Properties ----------------------------------------------------------

    @property
    def address(self) -> str:
        """The agent's full UAM address (e.g., ``myagent::youam.network``)."""
        if self._address is None:
            raise RuntimeError(
                "Agent not yet connected. Call await agent.connect() first."
            )
        return self._address

    @property
    def version(self) -> str:
        """UAM package version."""
        from uam import __version__
        return __version__

    @property
    def public_key(self) -> str:
        """The agent's public key (base64-encoded Ed25519 verify key)."""
        return serialize_verify_key(self._key_manager.verify_key)

    @property
    def is_connected(self) -> bool:
        """Whether the agent has completed connection setup."""
        return self._connected

    def contact_card(self) -> dict:
        """Generate and return a signed contact card for this agent (SDK-07)."""
        if not self._connected:
            raise RuntimeError("Agent not connected. Call connect() first.")
        card = create_contact_card(
            address=self._address,
            display_name=self._config.display_name,
            relay=self._config.relay_ws_url,
            signing_key=self._key_manager.signing_key,
        )
        return contact_card_to_dict(card)

    # -- Lifecycle -----------------------------------------------------------

    async def connect(self) -> None:
        """Initialize the agent: load/generate keys, register, connect transport.

        Idempotent -- calling twice is safe.
        """
        if self._connected:
            return

        # 1. Load or generate keypair
        self._key_manager.load_or_generate(self._config.name)

        # 2. Check for stored token (returning user)
        stored_token = self._key_manager.load_token(self._config.name)

        if stored_token:
            # Returning user: use stored token
            self._token = stored_token
            self._address = f"{self._config.name}::{self._config.relay_domain}"
        elif self._auto_register:
            # First-run: register with relay
            await self._register_with_relay()
        else:
            raise UAMError(
                "No stored token and auto_register=False. "
                "Register manually or set auto_register=True."
            )

        # 3. Create and connect transport
        self._transport = create_transport(
            self._config,
            self._token,
            self._address,
        )
        await self._transport.connect()

        # 4. Open contact book
        await self._contact_book.open()

        self._connected = True

        # 5. Sweep expired handshakes (HAND-03)
        await self._sweep_expired_handshakes()

    async def close(self) -> None:
        """Disconnect the transport and clean up resources."""
        # Close contact book first
        await self._contact_book.close()
        if self._transport:
            await self._transport.disconnect()
        self._connected = False

    async def __aenter__(self) -> Agent:
        """Async context manager entry: connect and return self."""
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit: close transport."""
        await self.close()

    # -- Messaging -----------------------------------------------------------

    async def send(
        self,
        to_address: str,
        message: str,
        *,
        thread_id: str | None = None,
        attachments: list[dict] | None = None,
    ) -> str:
        """Send an encrypted, signed message.  Returns the message_id.

        Steps:
          1. Ensure connected
          2. Resolve recipient's public key
          3. Initiate handshake if first contact
          4. Create signed, encrypted envelope
          5. Send via transport
        """
        await self._ensure_connected()

        # Resolve recipient's verify key (Ed25519)
        recipient_vk = await self._resolve_public_key(to_address)

        # Check if first contact -- send handshake if needed
        if not self._contact_book.is_known(to_address):
            await self._initiate_handshake(to_address, recipient_vk)

        # Create signed, encrypted envelope
        envelope = create_envelope(
            from_address=self._address,
            to_address=to_address,
            message_type=MessageType.MESSAGE,
            payload_plaintext=message.encode("utf-8"),
            signing_key=self._key_manager.signing_key,
            recipient_verify_key=recipient_vk,
            thread_id=thread_id,
            media_type="text/plain",
            attachments=attachments,
        )

        # Send via transport (with multi-relay failover -- CARD-06)
        wire = to_wire_dict(envelope)
        relay_urls = await self._get_relay_urls(to_address)
        if (
            relay_urls is not None
            and len(relay_urls) == 1
            and relay_urls[0] == self._config.relay_url
        ):
            # Same relay -- use existing transport (no failover overhead)
            await self._transport.send(wire)
        elif relay_urls is not None and len(relay_urls) > 0:
            # Multi-relay or cross-relay: try each in order
            await self._try_send_with_failover(wire, relay_urls)
        else:
            # No relay info -- fall back to own transport
            await self._transport.send(wire)
        return envelope.message_id

    async def inbox(self, limit: int = 50) -> list[ReceivedMessage]:
        """Retrieve, decrypt, and verify pending messages.

        Returns a list of ReceivedMessage data objects.
        Silently drops messages with invalid signatures or decryption errors.
        """
        await self._ensure_connected()

        # Sweep expired handshakes (HAND-03)
        await self._sweep_expired_handshakes()

        raw_messages = await self._transport.receive(limit=limit)
        result = []
        for raw in raw_messages:
            msg = await self._process_inbound(raw)
            if msg is not None:
                result.append(msg)
                # Auto-send receipt.read for user messages (RCPT-01)
                await self._send_read_receipt(msg)
        return result

    # -- Trust management (HAND-02, HAND-04) ---------------------------------

    async def pending(self) -> list[dict]:
        """List pending handshake requests (HAND-02)."""
        await self._ensure_connected()
        return await self._contact_book.get_pending()

    async def approve(self, address: str) -> None:
        """Approve a pending handshake request (HAND-02).

        Adds the sender to contacts with trust_source='explicit-approval'
        and sends handshake.accept back.
        """
        await self._ensure_connected()

        # Find the pending entry
        pending_list = await self._contact_book.get_pending()
        entry = next((p for p in pending_list if p["address"] == address), None)
        if entry is None:
            raise UAMError(f"No pending handshake from {address}")

        # Parse and verify the stored contact card
        card_dict = json.loads(entry["contact_card"])
        card = contact_card_from_dict(card_dict)
        verify_contact_card(card)

        # Add to contacts with trust_source tracking
        await self._contact_book.add_contact(
            address=card.address,
            public_key=card.public_key,
            display_name=card.display_name,
            trust_state="trusted",
            trust_source="explicit-approval",
        )

        # Remove from pending
        await self._contact_book.remove_pending(address)

        # Send handshake.accept back
        sender_vk = deserialize_verify_key(card.public_key)
        await self._handshake._send_accept(self, address, sender_vk)

    async def deny(self, address: str) -> None:
        """Deny a pending handshake request (HAND-02).

        Removes the entry from pending and sends handshake.deny.
        """
        await self._ensure_connected()

        pending_list = await self._contact_book.get_pending()
        entry = next((p for p in pending_list if p["address"] == address), None)
        if entry is None:
            raise UAMError(f"No pending handshake from {address}")

        # Parse contact card for sender's public key
        card_dict = json.loads(entry["contact_card"])
        card = contact_card_from_dict(card_dict)
        sender_vk = deserialize_verify_key(card.public_key)

        # Remove from pending
        await self._contact_book.remove_pending(address)

        # Send handshake.deny
        await self._handshake._send_deny(self, address, sender_vk)

    async def block(self, pattern: str) -> None:
        """Block an address or domain pattern (HAND-04).

        Patterns: exact address ``'spammer::evil.com'`` or domain ``'*::evil.com'``.
        """
        await self._ensure_connected()
        await self._contact_book.add_block(pattern)

    async def unblock(self, pattern: str) -> None:
        """Remove a block pattern (HAND-04)."""
        await self._ensure_connected()
        await self._contact_book.remove_block(pattern)

    # -- Domain verification (DNS-02) ----------------------------------------

    async def verify_domain(
        self,
        domain: str,
        *,
        timeout: float = 300.0,
        poll_interval: float = 10.0,
    ) -> bool:
        """Verify domain ownership via relay endpoint (DNS-02).

        Polls ``POST /api/v1/verify-domain`` until the relay confirms
        DNS TXT (or HTTPS fallback) verification succeeds, or *timeout*
        seconds elapse.

        Returns ``True`` if verified, ``False`` on timeout.
        """
        from uam.sdk.dns_verifier import generate_txt_record

        await self._ensure_connected()

        expected_txt = generate_txt_record(
            self.public_key, self._config.relay_url
        )
        logger.info(
            "Expected TXT record at _uam.%s: %s", domain, expected_txt
        )

        start = time.monotonic()
        while (time.monotonic() - start) < timeout:
            async with httpx.AsyncClient(timeout=30.0) as client:
                try:
                    resp = await client.post(
                        f"{self._config.relay_url}/api/v1/verify-domain",
                        json={"domain": domain},
                        headers={"Authorization": f"Bearer {self._token}"},
                    )
                    if resp.status_code == 200:
                        result = resp.json()
                        if result.get("status") == "verified":
                            return True
                except httpx.HTTPError:
                    logger.debug(
                        "verify-domain request failed, retrying in %ss",
                        poll_interval,
                    )
            await asyncio.sleep(poll_interval)

        return False

    def verify_domain_sync(self, domain: str, **kwargs) -> bool:
        """Synchronous wrapper for verify_domain()."""
        return _run_sync(self.verify_domain(domain, **kwargs))

    # -- Sync wrappers (SDK-04) ---------------------------------------------

    def send_sync(self, to_address: str, message: str, **kwargs) -> str:
        """Synchronous wrapper for send()."""
        return _run_sync(self.send(to_address, message, **kwargs))

    def inbox_sync(self, limit: int = 50) -> list[ReceivedMessage]:
        """Synchronous wrapper for inbox()."""
        return _run_sync(self.inbox(limit=limit))

    def connect_sync(self) -> None:
        """Synchronous wrapper for connect()."""
        _run_sync(self.connect())

    def close_sync(self) -> None:
        """Synchronous wrapper for close()."""
        _run_sync(self.close())

    def pending_sync(self) -> list[dict]:
        """Synchronous wrapper for pending()."""
        return _run_sync(self.pending())

    def approve_sync(self, address: str) -> None:
        """Synchronous wrapper for approve()."""
        _run_sync(self.approve(address))

    def deny_sync(self, address: str) -> None:
        """Synchronous wrapper for deny()."""
        _run_sync(self.deny(address))

    def block_sync(self, pattern: str) -> None:
        """Synchronous wrapper for block()."""
        _run_sync(self.block(pattern))

    def unblock_sync(self, pattern: str) -> None:
        """Synchronous wrapper for unblock()."""
        _run_sync(self.unblock(pattern))

    # -- Internal methods ----------------------------------------------------

    # -- Multi-relay failover (CARD-06) --------------------------------------

    async def _get_relay_urls(self, to_address: str) -> list[str] | None:
        """Return ordered relay URLs for *to_address* (CARD-06).

        Resolution order:
        1. Contact book ``relays`` array (multi-relay from stored card)
        2. Contact book ``relay`` (single relay, wrapped in list)
        3. ``[self._config.relay_url]`` (default: send to own relay)
        """
        urls = await self._contact_book.get_relay_urls(to_address)
        if urls is not None:
            return urls
        # Fallback: own relay
        return [self._config.relay_url]

    async def _try_send_with_failover(
        self,
        wire: dict,
        relay_urls: list[str],
    ) -> None:
        """Try sending *wire* envelope to each relay URL in order (CARD-06).

        Uses transient ``httpx`` POST requests (not the agent's persistent
        transport) so the envelope can be delivered to any relay that
        hosts the recipient.

        On success (2xx), returns immediately.  On connection/HTTP error,
        logs a warning and tries the next relay.  If ALL relays fail,
        raises the last exception.
        """
        last_error: Exception | None = None
        for url in relay_urls:
            # Normalise: strip trailing '/ws' or '/ws/' to get base HTTP URL,
            # then ensure we hit the HTTP send endpoint.
            base = url.rstrip("/")
            if base.endswith("/ws"):
                base = base[:-3]
            # Convert wss:// -> https:// and ws:// -> http:// for POST
            base = base.replace("wss://", "https://").replace("ws://", "http://")
            send_url = f"{base}/api/v1/send"

            try:
                async with httpx.AsyncClient(timeout=10.0) as client:
                    resp = await client.post(
                        send_url,
                        json={"envelope": wire},
                        headers={"Authorization": f"Bearer {self._token}"},
                    )
                    resp.raise_for_status()
                logger.debug("Sent envelope via relay %s", url)
                return
            except (
                httpx.ConnectError,
                httpx.ConnectTimeout,
                httpx.TimeoutException,
                httpx.HTTPStatusError,
            ) as exc:
                last_error = exc
                logger.warning(
                    "Relay %s failed (%s), trying next relay", url, exc
                )

        # All relays failed
        if last_error is not None:
            raise last_error
        raise UAMError("No relay URLs to try")

    async def _ensure_connected(self) -> None:
        """Lazily connect if not already connected."""
        if not self._connected:
            await self.connect()

    async def _resolve_public_key(self, to_address: str):
        """Resolve a recipient's public key, checking contact book first.

        Returns a VerifyKey. Caches resolved keys in the contact book.
        """
        # Check contact book first
        pk_str = await self._contact_book.get_public_key(to_address)
        if pk_str is not None:
            return deserialize_verify_key(pk_str)

        # Not in contact book -- resolve via relay
        pk_str = await self._resolver.resolve_public_key(
            to_address, self._token, self._config.relay_url
        )

        # Cache in contact book (unverified until handshake completes)
        await self._contact_book.add_contact(
            to_address, pk_str, trust_state="unverified"
        )

        return deserialize_verify_key(pk_str)

    async def _get_sender_public_key(self, from_address: str) -> str | None:
        """Look up sender's public key from contact book."""
        return await self._contact_book.get_public_key(from_address)

    async def _initiate_handshake(self, to_address: str, recipient_vk) -> None:
        """Send a handshake request to a new contact."""
        wire = await self._handshake.create_handshake_request(
            self, to_address, recipient_vk
        )
        await self._transport.send(wire)

        # Mark as handshake-sent in contact book
        await self._contact_book.add_contact(
            to_address,
            serialize_verify_key(recipient_vk),
            trust_state="handshake-sent",
        )

    async def _process_inbound(self, raw: dict) -> ReceivedMessage | None:
        """Process a single inbound envelope: verify, decrypt, handle handshakes.

        Returns None for invalid messages or handshake protocol messages.
        """
        # Parse envelope
        envelope = from_wire_dict(raw)

        # Check block list BEFORE expensive crypto (HAND-04)
        if self._contact_book.is_blocked(envelope.from_address):
            logger.debug(
                "Dropped message from blocked sender %s", envelope.from_address
            )
            return None

        # Look up sender's public key for verification
        sender_pk_str = await self._get_sender_public_key(envelope.from_address)
        if sender_pk_str is None:
            # Unknown sender -- try resolving from relay
            try:
                sender_pk_str = await self._resolver.resolve_public_key(
                    envelope.from_address, self._token, self._config.relay_url
                )
            except Exception:
                logger.warning(
                    "Cannot resolve sender public key for %s, skipping message %s",
                    envelope.from_address,
                    envelope.message_id,
                )
                return None

        sender_vk = deserialize_verify_key(sender_pk_str)

        # Verify signature (SEC-03: mandatory)
        try:
            verify_envelope(envelope, sender_vk)
        except SignatureVerificationError:
            logger.warning(
                "Invalid signature on message %s from %s, rejecting",
                envelope.message_id,
                envelope.from_address,
            )
            return None  # Silently reject unsigned/invalid messages

        # Handle handshake messages (not user-visible)
        if envelope.type in (
            MessageType.HANDSHAKE_REQUEST.value,
            MessageType.HANDSHAKE_ACCEPT.value,
            MessageType.HANDSHAKE_DENY.value,
        ):
            return await self._handshake.handle_inbound(self, envelope, sender_vk)

        # For non-auto-accept policies, filter messages from unapproved senders (HAND-01, CARD-05)
        if self._handshake._trust_policy != "auto-accept":
            trust = await self._contact_book.get_trust_state(envelope.from_address)
            if trust not in ("trusted", "verified"):
                logger.info(
                    "Filtered message from unapproved sender %s (trust=%s, policy=%s)",
                    envelope.from_address,
                    trust,
                    self._handshake._trust_policy,
                )
                return None

        # Decrypt payload (SEC-04: mandatory)
        try:
            plaintext_bytes = decrypt_payload(
                envelope.payload,
                self._key_manager.signing_key,
                sender_vk,
            )
        except DecryptionError:
            logger.warning(
                "Decryption failed for message %s from %s, skipping",
                envelope.message_id,
                envelope.from_address,
            )
            return None

        # Build ReceivedMessage data object
        return ReceivedMessage(
            message_id=envelope.message_id,
            from_address=envelope.from_address,
            to_address=envelope.to_address,
            content=plaintext_bytes.decode("utf-8"),
            timestamp=envelope.timestamp,
            type=envelope.type,
            thread_id=envelope.thread_id,
            reply_to=envelope.reply_to,
            media_type=envelope.media_type,
            verified=True,
        )

    async def _sweep_expired_handshakes(self) -> None:
        """Sweep expired pending handshakes and send receipt.failed (HAND-03)."""
        expired = await self._contact_book.get_expired_pending(days=7)
        for entry in expired:
            try:
                # Extract public key from stored contact card
                card_dict = json.loads(entry["contact_card"])
                card = contact_card_from_dict(card_dict)
                recipient_vk = deserialize_verify_key(card.public_key)

                # Send receipt.failed
                fail_payload = json.dumps({
                    "reason": "handshake_expired",
                    "original_from": entry["address"],
                }).encode("utf-8")
                envelope = create_envelope(
                    from_address=self._address,
                    to_address=entry["address"],
                    message_type=MessageType.RECEIPT_FAILED,
                    payload_plaintext=fail_payload,
                    signing_key=self._key_manager.signing_key,
                    recipient_verify_key=recipient_vk,
                )
                wire = to_wire_dict(envelope)
                await self._transport.send(wire)
                logger.info(
                    "Sent receipt.failed (handshake_expired) to %s",
                    entry["address"],
                )
            except Exception:
                logger.warning(
                    "Failed to send receipt.failed to %s",
                    entry["address"],
                    exc_info=True,
                )

            # Remove from pending regardless of whether receipt.failed was sent
            await self._contact_book.remove_pending(entry["address"])

    async def _send_read_receipt(self, msg: ReceivedMessage) -> None:
        """Send receipt.read back to the sender (RCPT-01).

        Fire-and-forget: errors are logged at debug level and never propagated.
        Anti-loop guard: receipts, handshakes, and session messages are skipped.
        """
        # Anti-loop: never generate receipts for protocol messages
        if msg.type.startswith(("receipt.", "handshake.", "session.")):
            return

        try:
            # Resolve sender's public key
            sender_pk_str = await self._get_sender_public_key(msg.from_address)
            if sender_pk_str is None:
                logger.debug(
                    "Cannot send receipt.read to %s: public key unknown",
                    msg.from_address,
                )
                return

            sender_vk = deserialize_verify_key(sender_pk_str)

            # Build receipt payload with original message_id
            receipt_payload = json.dumps(
                {"message_id": msg.message_id}
            ).encode("utf-8")

            # Create signed+encrypted envelope
            envelope = create_envelope(
                from_address=self._address,
                to_address=msg.from_address,
                message_type=MessageType.RECEIPT_READ,
                payload_plaintext=receipt_payload,
                signing_key=self._key_manager.signing_key,
                recipient_verify_key=sender_vk,
            )

            # Send via transport (fire-and-forget)
            wire = to_wire_dict(envelope)
            await self._transport.send(wire)
            logger.debug(
                "Sent receipt.read to %s for message %s",
                msg.from_address,
                msg.message_id,
            )
        except Exception:
            logger.debug(
                "Failed to send receipt.read to %s for message %s",
                msg.from_address,
                msg.message_id,
                exc_info=True,
            )

    async def _register_with_relay(self) -> None:
        """Register with the relay server.

        Calls ``POST /api/v1/register`` with agent name and public key.
        Stores the returned API key on disk.
        """
        public_key_str = serialize_verify_key(self._key_manager.verify_key)

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                f"{self._config.relay_url}/api/v1/register",
                json={
                    "agent_name": self._config.name,
                    "public_key": public_key_str,
                },
            )

        if resp.status_code == 409:
            raise UAMError(
                f"Address already registered with a different key: "
                f"{self._config.name}::{self._config.relay_domain}"
            )

        if resp.status_code != 200:
            raise UAMError(
                f"Registration failed: {resp.status_code} {resp.text}"
            )

        data = resp.json()
        self._address = data["address"]
        self._token = data["token"]

        # Persist token for returning-user flow
        self._key_manager.save_token(self._config.name, self._token)

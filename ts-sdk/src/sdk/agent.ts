/**
 * Agent class -- the primary SDK interface (SDK-01).
 *
 * Provides send(), inbox(), handshake flow, contact management,
 * trust policies, approve/deny/block/unblock.
 *
 * Matches Python agent.py API surface.
 */

import {
  MessageType,
  UAMError,
  SignatureVerificationError,
  DecryptionError,
  sodiumReady,
  createEnvelope,
  verifyEnvelope,
  decryptPayload,
  toWireDict,
  fromWireDict,
  serializeVerifyKey,
  deserializeVerifyKey,
  createContactCard,
  contactCardToDict,
  contactCardFromDict,
  verifyContactCard,
  type MessageEnvelope,
} from "../protocol/index.js";
import { SDKConfig } from "./config.js";
import { KeyManager } from "./key-manager.js";
import type { ReceivedMessage } from "./message.js";
import { ContactBook } from "./contact-book.js";
import { HandshakeManager } from "./handshake.js";
import { type AddressResolver, SmartResolver } from "./resolver.js";
import { createTransport, type TransportBase } from "./transport/index.js";

export class Agent {
  /** @internal */
  readonly _config: SDKConfig;
  /** @internal */
  readonly _keyManager: KeyManager;
  /** @internal */
  _transport: TransportBase | null = null;

  private _resolver: AddressResolver;
  private _address: string | null = null;
  private _token: string | null = null;
  private _connected: boolean = false;
  private _autoRegister: boolean;

  /** @internal */
  readonly _contactBook: ContactBook;
  /** @internal */
  readonly _handshake: HandshakeManager;

  /**
   * Create an Agent. No I/O happens here -- call connect() to initialize.
   */
  constructor(
    name: string,
    options?: {
      relay?: string | null;
      domain?: string | null;
      keyDir?: string | null;
      autoRegister?: boolean;
      displayName?: string | null;
      transport?: string;
      trustPolicy?: string;
    }
  ) {
    this._config = new SDKConfig({
      name,
      relayUrl: options?.relay,
      relayDomain: options?.domain ?? undefined,
      keyDir: options?.keyDir,
      displayName: options?.displayName ?? name,
      transportType: options?.transport ?? "websocket",
      trustPolicy: options?.trustPolicy ?? "auto-accept",
    });
    this._keyManager = new KeyManager(this._config.keyDir);
    this._resolver = new SmartResolver(this._config.relayDomain);
    this._autoRegister = options?.autoRegister ?? true;

    // Contact management
    this._contactBook = new ContactBook(this._config.dataDir);
    this._handshake = new HandshakeManager(
      this._contactBook,
      this._config.trustPolicy
    );
  }

  // -- Properties ----------------------------------------------------------

  /** The agent's full UAM address (e.g., 'myagent::youam.network'). */
  get address(): string {
    if (this._address === null) {
      throw new Error(
        "Agent not yet connected. Call await agent.connect() first."
      );
    }
    return this._address;
  }

  /** UAM SDK version. */
  get version(): string {
    return "0.1.0";
  }

  /** The agent's public key (base64-encoded Ed25519 verify key). */
  get publicKey(): string {
    return serializeVerifyKey(this._keyManager.verifyKey);
  }

  /** Whether the agent has completed connection setup. */
  get isConnected(): boolean {
    return this._connected;
  }

  /**
   * Generate and return a signed contact card for this agent.
   */
  async contactCard(): Promise<Record<string, unknown>> {
    if (!this._connected) {
      throw new Error("Agent not connected. Call connect() first.");
    }
    const card = await createContactCard(
      this._address!,
      this._config.displayName,
      this._config.relayWsUrl,
      this._keyManager.signingKey
    );
    return contactCardToDict(card);
  }

  // -- Lifecycle -----------------------------------------------------------

  /**
   * Initialize the agent: load/generate keys, register, connect transport.
   *
   * Idempotent -- calling twice is safe.
   */
  async connect(): Promise<void> {
    if (this._connected) {
      return;
    }

    // 0. Ensure sodium is ready
    await sodiumReady;

    // 1. Load or generate keypair
    this._keyManager.loadOrGenerate(this._config.name);

    // 2. Check for stored token (returning user)
    const storedToken = this._keyManager.loadToken(this._config.name);

    if (storedToken) {
      // Returning user: use stored token
      this._token = storedToken;
      this._address = `${this._config.name}::${this._config.relayDomain}`;
    } else if (this._autoRegister) {
      // First-run: register with relay
      await this._registerWithRelay();
    } else {
      throw new UAMError(
        "No stored token and autoRegister=false. " +
          "Register manually or set autoRegister=true."
      );
    }

    // 3. Create and connect transport
    this._transport = createTransport(
      this._config,
      this._token!,
      this._address!
    );
    await this._transport.connect();

    // 4. Open contact book
    this._contactBook.open();

    this._connected = true;

    // 5. Sweep expired handshakes (HAND-03)
    await this._sweepExpiredHandshakes();
  }

  /**
   * Disconnect the transport and clean up resources.
   */
  async close(): Promise<void> {
    // Close contact book first
    this._contactBook.close();
    if (this._transport) {
      await this._transport.disconnect();
    }
    this._connected = false;
  }

  // -- Messaging -----------------------------------------------------------

  /**
   * Send an encrypted, signed message. Returns the message_id.
   */
  async send(
    toAddress: string,
    message: string,
    options?: {
      threadId?: string;
      attachments?: Array<Record<string, unknown>>;
    }
  ): Promise<string> {
    await this._ensureConnected();

    // Resolve recipient's verify key (Ed25519)
    const recipientVk = await this._resolvePublicKey(toAddress);

    // Check if first contact -- send handshake if needed
    if (!this._contactBook.isKnown(toAddress)) {
      await this._initiateHandshake(toAddress, recipientVk);
    }

    // Create signed, encrypted envelope
    const envelope = await createEnvelope(
      this._address!,
      toAddress,
      MessageType.MESSAGE,
      new TextEncoder().encode(message),
      this._keyManager.signingKey,
      recipientVk,
      {
        threadId: options?.threadId,
        mediaType: "text/plain",
        attachments: options?.attachments,
      }
    );

    // Send via transport (with multi-relay failover -- CARD-06)
    const wire = toWireDict(envelope);
    const relayUrls = await this._getRelayUrls(toAddress);
    if (
      relayUrls !== null &&
      relayUrls.length === 1 &&
      relayUrls[0] === this._config.relayUrl
    ) {
      // Same relay -- use existing transport (no failover overhead)
      await this._transport!.send(wire);
    } else if (relayUrls !== null && relayUrls.length > 0) {
      // Multi-relay or cross-relay: try each in order
      await this._trySendWithFailover(wire, relayUrls);
    } else {
      // No relay info -- fall back to own transport
      await this._transport!.send(wire);
    }

    return envelope.messageId;
  }

  /**
   * Retrieve, decrypt, and verify pending messages.
   *
   * Returns a list of ReceivedMessage data objects.
   * Silently drops messages with invalid signatures or decryption errors.
   */
  async inbox(limit: number = 50): Promise<ReceivedMessage[]> {
    await this._ensureConnected();

    // Sweep expired handshakes
    await this._sweepExpiredHandshakes();

    const rawMessages = await this._transport!.receive(limit);
    const result: ReceivedMessage[] = [];
    for (const raw of rawMessages) {
      const msg = await this._processInbound(raw);
      if (msg !== null) {
        result.push(msg);
        // Auto-send receipt.read for user messages (RCPT-01)
        await this._sendReadReceipt(msg);
      }
    }
    return result;
  }

  // -- Trust management (HAND-02, HAND-04) ---------------------------------

  /** List pending handshake requests. */
  async pending(): Promise<Array<{ address: string; contactCard: string; receivedAt: string }>> {
    await this._ensureConnected();
    return this._contactBook.getPending();
  }

  /**
   * Approve a pending handshake request.
   *
   * Adds the sender to contacts with trust_source='explicit-approval'
   * and sends handshake.accept back.
   */
  async approve(address: string): Promise<void> {
    await this._ensureConnected();

    const pendingList = this._contactBook.getPending();
    const entry = pendingList.find((p) => p.address === address);
    if (!entry) {
      throw new UAMError(`No pending handshake from ${address}`);
    }

    // Parse and verify the stored contact card
    const cardDict = JSON.parse(entry.contactCard) as Record<string, unknown>;
    const card = contactCardFromDict(cardDict);
    verifyContactCard(card);

    // Add to contacts with trust_source tracking
    this._contactBook.addContact(card.address, card.publicKey, {
      displayName: card.displayName,
      trustState: "trusted",
      trustSource: "explicit-approval",
    });

    // Remove from pending
    this._contactBook.removePending(address);

    // Send handshake.accept back
    const senderVk = deserializeVerifyKey(card.publicKey);
    await this._handshake._sendAccept(this, address, senderVk);
  }

  /**
   * Deny a pending handshake request.
   *
   * Removes the entry from pending and sends handshake.deny.
   */
  async deny(address: string): Promise<void> {
    await this._ensureConnected();

    const pendingList = this._contactBook.getPending();
    const entry = pendingList.find((p) => p.address === address);
    if (!entry) {
      throw new UAMError(`No pending handshake from ${address}`);
    }

    // Parse contact card for sender's public key
    const cardDict = JSON.parse(entry.contactCard) as Record<string, unknown>;
    const card = contactCardFromDict(cardDict);
    const senderVk = deserializeVerifyKey(card.publicKey);

    // Remove from pending
    this._contactBook.removePending(address);

    // Send handshake.deny
    await this._handshake._sendDeny(this, address, senderVk);
  }

  /**
   * Block an address or domain pattern (HAND-04).
   */
  async block(pattern: string): Promise<void> {
    await this._ensureConnected();
    this._contactBook.addBlock(pattern);
  }

  /**
   * Remove a block pattern (HAND-04).
   */
  async unblock(pattern: string): Promise<void> {
    await this._ensureConnected();
    this._contactBook.removeBlock(pattern);
  }

  // -- Internal methods ----------------------------------------------------

  /** Multi-relay failover (CARD-06). */
  private async _getRelayUrls(toAddress: string): Promise<string[] | null> {
    const urls = this._contactBook.getRelayUrls(toAddress);
    if (urls !== null) {
      return urls;
    }
    return [this._config.relayUrl];
  }

  /**
   * Try sending wire envelope to each relay URL in order (CARD-06).
   *
   * Uses transient fetch POST requests so the envelope can be delivered
   * to any relay that hosts the recipient.
   */
  private async _trySendWithFailover(
    wire: Record<string, unknown>,
    relayUrls: string[]
  ): Promise<void> {
    let lastError: Error | null = null;

    for (const url of relayUrls) {
      // Normalize: strip trailing '/ws', convert ws:// -> http://
      let base = url.replace(/\/+$/, "");
      if (base.endsWith("/ws")) {
        base = base.slice(0, -3);
      }
      base = base.replace("wss://", "https://").replace("ws://", "http://");
      const sendUrl = `${base}/api/v1/send`;

      try {
        const resp = await fetch(sendUrl, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${this._token}`,
          },
          body: JSON.stringify({ envelope: wire }),
          signal: AbortSignal.timeout(10000),
        });
        if (!resp.ok) {
          throw new Error(`HTTP ${resp.status}`);
        }
        return; // Success
      } catch (err) {
        lastError = err instanceof Error ? err : new Error(String(err));
      }
    }

    if (lastError !== null) {
      throw lastError;
    }
    throw new UAMError("No relay URLs to try");
  }

  private async _ensureConnected(): Promise<void> {
    if (!this._connected) {
      await this.connect();
    }
  }

  /**
   * Resolve a recipient's public key, checking contact book first.
   */
  private async _resolvePublicKey(toAddress: string): Promise<Uint8Array> {
    // Check contact book first
    const pkStr = this._contactBook.getPublicKey(toAddress);
    if (pkStr !== null) {
      return deserializeVerifyKey(pkStr);
    }

    // Not in contact book -- resolve via relay
    const resolved = await this._resolver.resolvePublicKey(
      toAddress,
      this._token!,
      this._config.relayUrl
    );

    // Cache in contact book (unverified until handshake completes)
    this._contactBook.addContact(toAddress, resolved, {
      trustState: "unverified",
    });

    return deserializeVerifyKey(resolved);
  }

  private async _initiateHandshake(
    toAddress: string,
    recipientVk: Uint8Array
  ): Promise<void> {
    const wire = await this._handshake.createHandshakeRequest(
      this,
      toAddress,
      recipientVk
    );
    await this._transport!.send(wire);

    // Mark as handshake-sent in contact book
    this._contactBook.addContact(
      toAddress,
      serializeVerifyKey(recipientVk),
      { trustState: "handshake-sent" }
    );
  }

  /**
   * Process a single inbound envelope: verify, decrypt, handle handshakes.
   *
   * Returns null for invalid messages or handshake protocol messages.
   */
  private async _processInbound(
    raw: Record<string, unknown>
  ): Promise<ReceivedMessage | null> {
    // Parse envelope
    const envelope = fromWireDict(raw);

    // Check block list BEFORE expensive crypto (HAND-04)
    if (this._contactBook.isBlocked(envelope.fromAddress)) {
      return null;
    }

    // Look up sender's public key for verification
    let senderPkStr = this._contactBook.getPublicKey(envelope.fromAddress);
    if (senderPkStr === null) {
      // Unknown sender -- try resolving from relay
      try {
        senderPkStr = await this._resolver.resolvePublicKey(
          envelope.fromAddress,
          this._token!,
          this._config.relayUrl
        );
      } catch {
        return null;
      }
    }

    const senderVk = deserializeVerifyKey(senderPkStr);

    // Verify signature (SEC-03: mandatory)
    try {
      verifyEnvelope(envelope, senderVk);
    } catch (err) {
      if (err instanceof SignatureVerificationError) {
        return null; // Silently reject unsigned/invalid messages
      }
      throw err;
    }

    // Handle handshake messages (not user-visible)
    if (
      envelope.type === MessageType.HANDSHAKE_REQUEST ||
      envelope.type === MessageType.HANDSHAKE_ACCEPT ||
      envelope.type === MessageType.HANDSHAKE_DENY
    ) {
      return this._handshake.handleInbound(this, envelope, senderVk);
    }

    // For non-auto-accept policies, filter messages from unapproved senders
    if (this._handshake._trustPolicy !== "auto-accept") {
      const trust = this._contactBook.getTrustState(envelope.fromAddress);
      if (trust !== "trusted" && trust !== "verified") {
        return null;
      }
    }

    // Decrypt payload (SEC-04: mandatory)
    let plaintextBytes: Uint8Array;
    try {
      plaintextBytes = decryptPayload(
        envelope.payload,
        this._keyManager.signingKey,
        senderVk
      );
    } catch (err) {
      if (err instanceof DecryptionError) {
        return null;
      }
      throw err;
    }

    // Build ReceivedMessage data object
    return Object.freeze({
      messageId: envelope.messageId,
      fromAddress: envelope.fromAddress,
      toAddress: envelope.toAddress,
      content: new TextDecoder().decode(plaintextBytes),
      timestamp: envelope.timestamp,
      type: envelope.type,
      threadId: envelope.threadId,
      replyTo: envelope.replyTo,
      mediaType: envelope.mediaType,
      verified: true,
    });
  }

  /**
   * Sweep expired pending handshakes and send receipt.failed (HAND-03).
   */
  private async _sweepExpiredHandshakes(): Promise<void> {
    const expired = this._contactBook.getExpiredPending(7);
    for (const entry of expired) {
      try {
        const cardDict = JSON.parse(entry.contactCard) as Record<
          string,
          unknown
        >;
        const card = contactCardFromDict(cardDict);
        const recipientVk = deserializeVerifyKey(card.publicKey);

        const failPayload = JSON.stringify({
          reason: "handshake_expired",
          original_from: entry.address,
        });
        const envelope = await createEnvelope(
          this._address!,
          entry.address,
          MessageType.RECEIPT_FAILED,
          new TextEncoder().encode(failPayload),
          this._keyManager.signingKey,
          recipientVk
        );
        const wire = toWireDict(envelope);
        await this._transport!.send(wire);
      } catch {
        // Failed to send receipt.failed -- ignore
      }

      // Remove from pending regardless
      this._contactBook.removePending(entry.address);
    }
  }

  /**
   * Send receipt.read back to the sender (RCPT-01).
   *
   * Fire-and-forget: errors are never propagated.
   * Anti-loop guard: receipts, handshakes, and session messages are skipped.
   */
  private async _sendReadReceipt(msg: ReceivedMessage): Promise<void> {
    // Anti-loop: never generate receipts for protocol messages
    if (
      msg.type.startsWith("receipt.") ||
      msg.type.startsWith("handshake.") ||
      msg.type.startsWith("session.")
    ) {
      return;
    }

    try {
      const senderPkStr = this._contactBook.getPublicKey(msg.fromAddress);
      if (senderPkStr === null) return;

      const senderVk = deserializeVerifyKey(senderPkStr);

      const receiptPayload = JSON.stringify({
        message_id: msg.messageId,
      });
      const envelope = await createEnvelope(
        this._address!,
        msg.fromAddress,
        MessageType.RECEIPT_READ,
        new TextEncoder().encode(receiptPayload),
        this._keyManager.signingKey,
        senderVk
      );

      const wire = toWireDict(envelope);
      await this._transport!.send(wire);
    } catch {
      // Fire-and-forget
    }
  }

  /**
   * Register with the relay server.
   *
   * Calls POST /api/v1/register with agent name and public key.
   * Stores the returned API key on disk.
   */
  private async _registerWithRelay(): Promise<void> {
    const publicKeyStr = serializeVerifyKey(this._keyManager.verifyKey);

    const resp = await fetch(
      `${this._config.relayUrl}/api/v1/register`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          agent_name: this._config.name,
          public_key: publicKeyStr,
        }),
      }
    );

    if (resp.status === 409) {
      throw new UAMError(
        `Address already registered with a different key: ` +
          `${this._config.name}::${this._config.relayDomain}`
      );
    }

    if (!resp.ok) {
      const text = await resp.text();
      throw new UAMError(
        `Registration failed: ${resp.status} ${text}`
      );
    }

    const data = (await resp.json()) as Record<string, unknown>;
    this._address = data["address"] as string;
    this._token = data["token"] as string;

    // Persist token for returning-user flow
    this._keyManager.saveToken(this._config.name, this._token);
  }
}

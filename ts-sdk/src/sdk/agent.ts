/**
 * Agent class -- the primary SDK interface (SDK-01).
 *
 * Provides send(), inbox(), handshake flow, contact management,
 * trust policies, approve/deny/block/unblock.
 *
 * Matches Python agent.py API surface.
 */

import { join } from "node:path";

import {
  parseAddress,
  MessageType,
  MAX_ENVELOPE_AGE,
  UAMError,
  KeyPinningError,
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
  signMessage,
  utcTimestamp,
  createContactCard,
  contactCardToDict,
  contactCardFromDict,
  verifyContactCard,
  type MessageEnvelope,
} from "../protocol/index.js";
import { SDK_VERSION } from "../version.js";
import { SDKConfig } from "./config.js";
import { RELAY_META_FEATURE, relayVouches } from "./freshness.js";
import { KeyManager } from "./key-manager.js";
import type { ReceivedMessage } from "./message.js";
import { ContactBook } from "./contact-book.js";
import { HandshakeManager, bindCardToEnvelope } from "./handshake.js";
import { log } from "./log.js";
import { type AddressResolver, SmartResolver } from "./resolver.js";
import { createTransport, type TransportBase } from "./transport/index.js";
import {
  PersistentReplayCache,
  DEFAULT_REPLAY_CACHE_CAPACITY,
} from "./replay-cache.js";

/** How long a relay's "no" to relay_meta is remembered. */
const RELAY_NO_MEMORY_MS = 60_000;

/** Replay cache capacity from UAM_REPLAY_CACHE_CAPACITY (default 1000000). */
function replayCacheCapacityFromEnv(): number {
  const raw = process.env["UAM_REPLAY_CACHE_CAPACITY"];
  if (raw === undefined || raw === "") {
    return DEFAULT_REPLAY_CACHE_CAPACITY;
  }
  const n = Number(raw);
  if (!Number.isInteger(n) || n < 1) {
    log.warn(
      `Ignoring invalid UAM_REPLAY_CACHE_CAPACITY=${JSON.stringify(raw)}; ` +
        `using ${DEFAULT_REPLAY_CACHE_CAPACITY}`
    );
    return DEFAULT_REPLAY_CACHE_CAPACITY;
  }
  return n;
}

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
   * @internal Wall clock in ms since the epoch, used by the inbound
   * freshness/expiry checks and the replay cache. Replaceable in tests.
   */
  _clock: () => number = () => Date.now();

  /**
   * @internal Inbound replay cache, keyed by (from address, message id).
   * Kept on disk under the data dir, so it outlives restarts and is shared by
   * every process using it; capacity from UAM_REPLAY_CACHE_CAPACITY.
   */
  readonly _replayCache: PersistentReplayCache;

  /** Whether our relay has said it writes relay_meta. */
  private _relayStamps: boolean = false;

  /** Until when, by _monotonic, to take the relay's last no as still true. */
  private _relayNoUntil: number = 0;

  /** @internal Monotonic clock in ms. Replaceable in tests. */
  _monotonic: () => number = () => performance.now();

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

    this._replayCache = new PersistentReplayCache(
      join(this._config.dataDir, "replay", "replay.db"),
      {
        capacity: replayCacheCapacityFromEnv(),
        now: () => this._clock(),
      }
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
    return SDK_VERSION;
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

    // Before registering, so its created_at predates anything signed to a
    // new agent. It opens itself on first use if this fails.
    try {
      await this._replayCache.open();
    } catch (err) {
      const reason = err instanceof Error ? err.message : String(err);
      log.warn(`Could not open the replay cache: ${reason}`);
    }

    // 2. Check for stored token (returning user)
    const storedToken = this._keyManager.loadToken(
      this._config.name,
      this._config.relayUrl
    );

    if (storedToken) {
      // Returning user: use stored token
      this._token = storedToken;
      this._useAddress(await this._storedAddress());
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
    await this._replayCache.close();
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

    // TOFU-05: require_verify blocks unverified first sends
    if (this._config.trustPolicy === "require_verify") {
      const trust = this._contactBook.getTrustState(toAddress);
      if (trust !== "pinned" && trust !== "verified") {
        throw new UAMError(
          `Trust policy 'require_verify' requires fingerprint ` +
            `verification before sending to ${toAddress}. ` +
            `Run: uam contact verify ${toAddress}`
        );
      }
    }

    // Resolve recipient's verify key (Ed25519). Read-only: the contact book
    // is not touched here.
    const recipientVk = await this._resolvePublicKey(toAddress);

    // Fire a handshake.request unless the key is already confirmed
    // (pinned/verified/trusted) or a request is already in flight
    // (handshake-sent). Any other state -- no row, provisional, unknown --
    // means the handshake never went out (or was lost). Gated on trust
    // state rather than row presence, as in the Python SDK.
    const trustState = this._contactBook.getTrustState(toAddress);
    if (
      trustState !== "pinned" &&
      trustState !== "verified" &&
      trustState !== "trusted" &&
      trustState !== "handshake-sent"
    ) {
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
   * Drops messages with invalid signatures or decryption errors. A message
   * that fails processing for any other reason (malformed envelope, bad
   * handshake payload, ...) is logged and dropped; it never aborts the
   * rest of the batch.
   */
  async inbox(limit: number = 50): Promise<ReceivedMessage[]> {
    await this._ensureConnected();

    // Sweep expired handshakes
    await this._sweepExpiredHandshakes();

    const rawMessages = await this._transport!.receive(limit);
    const result: ReceivedMessage[] = [];
    for (const raw of rawMessages) {
      let msg: ReceivedMessage | null;
      try {
        msg = await this._processInbound(raw);
      } catch (err) {
        log.warn(
          `Dropping inbound message ${String(raw["message_id"])} from ` +
            `${String(raw["from"])}: ` +
            `${err instanceof Error ? err.message : String(err)}`
        );
        continue;
      }
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

    // Re-bind the stored card to the address the request arrived from (the
    // pending row's key). Rows stored before request-side binding existed
    // may carry a card for a different address; never promote those.
    const senderVk = deserializeVerifyKey(card.publicKey);
    bindCardToEnvelope(card, { fromAddress: address }, senderVk);

    // Add to contacts with trust_source tracking
    this._contactBook.addContact(card.address, card.publicKey, {
      displayName: card.displayName,
      trustState: "trusted",
      trustSource: "explicit-approval",
    });

    // Remove from pending
    this._contactBook.removePending(address);

    // Send handshake.accept back
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

  // -- Domain verification (DNS-02) ----------------------------------------

  /**
   * Verify domain ownership via relay endpoint (DNS-02).
   *
   * Polls `POST /api/v1/verify-domain` until the relay confirms
   * DNS TXT (or HTTPS fallback) verification succeeds, or timeout
   * elapses.
   *
   * Returns `true` if verified, `false` on timeout.
   */
  async verifyDomain(
    domain: string,
    options?: { timeout?: number; pollInterval?: number }
  ): Promise<boolean> {
    const { generateTxtRecord } = await import("./dns-verifier.js");
    await this._ensureConnected();

    const timeout = options?.timeout ?? 300000; // 5 minutes
    const pollInterval = options?.pollInterval ?? 10000; // 10 seconds

    const expectedTxt = generateTxtRecord(
      this.publicKey,
      this._config.relayUrl
    );
    // Log expected TXT for user reference (they need to publish this)
    void expectedTxt;

    const start = Date.now();
    while (Date.now() - start < timeout) {
      try {
        const resp = await fetch(
          `${this._config.relayUrl}/api/v1/verify-domain`,
          {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              Authorization: `Bearer ${this._token}`,
            },
            body: JSON.stringify({ domain }),
            signal: AbortSignal.timeout(30000),
          }
        );
        if (resp.ok) {
          const result = (await resp.json()) as Record<string, unknown>;
          if (result["status"] === "verified") {
            return true;
          }
        }
      } catch {
        // Request failed, retry after poll interval
      }
      await new Promise((resolve) => setTimeout(resolve, pollInterval));
    }

    return false;
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
   *
   * Pure lookup: never writes to the contact book. The contact row is
   * created by _initiateHandshake (as "handshake-sent") once the request
   * has gone out, giving the lifecycle no row -> handshake-sent -> pinned.
   *
   * TOFU-01: Known contacts always use stored key (zero network I/O).
   * TOFU-03: Race-condition double-check after network resolve.
   * Raises KeyPinningError if a pinned contact's key doesn't match.
   */
  private async _resolvePublicKey(toAddress: string): Promise<Uint8Array> {
    // TOFU-01: Check contact book first (local-first, zero network I/O)
    const pkStr = this._contactBook.getPublicKey(toAddress);
    if (pkStr !== null) {
      // Known contact: always use stored key
      return deserializeVerifyKey(pkStr);
    }

    // Unknown contact: resolve from network
    const resolvedPkStr = await this._resolver.resolvePublicKey(
      toAddress,
      this._token!,
      this._config.relayUrl
    );

    // TOFU-03: Double-check no pinned key exists (race condition guard)
    const storedPk = this._contactBook.getPublicKey(toAddress);
    if (storedPk !== null && storedPk !== resolvedPkStr) {
      const trust = this._contactBook.getTrustState(toAddress);
      if (trust === "pinned" || trust === "trusted" || trust === "verified") {
        throw new KeyPinningError(
          `CRITICAL: Public key mismatch for ${toAddress}! ` +
            `Stored key does not match resolved key. ` +
            `This may indicate a relay MITM attack. ` +
            `To accept the new key: uam contact remove ${toAddress}`
        );
      }
    }

    return deserializeVerifyKey(resolvedPkStr);
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

    // Envelope checks, all AFTER signature verification so unauthenticated
    // input can never touch the replay cache. Order: recipient, freshness,
    // expiry, replay. The replay cache is the only stateful check and runs
    // last, so an envelope rejected by an earlier check records nothing.
    if (!(await this._passesInboundChecks(envelope, raw))) {
      return null;
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
      if (!this._contactBook.isTrustedOrVerified(envelope.fromAddress)) {
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
   * Recipient, freshness, expiry and replay checks for a signature-verified
   * inbound envelope. Returns false (and logs) when it must be dropped.
   * Matches the Python SDK's _process_inbound checks.
   */
  private async _passesInboundChecks(
    envelope: MessageEnvelope,
    raw: Record<string, unknown>
  ): Promise<boolean> {
    const id = envelope.messageId;
    const from = envelope.fromAddress;

    // (a) Recipient: drop envelopes addressed to someone else. Skipped when
    // no address is set yet (callers driving _processInbound directly).
    if (this._address !== null && envelope.toAddress !== this._address) {
      log.warn(
        `Dropped envelope ${id} from ${from} addressed to ` +
          `${envelope.toAddress} (we are ${this._address})`
      );
      return false;
    }

    const now = this._clock();

    // (b) Freshness: |now - timestamp| <= MAX_ENVELOPE_AGE, unless it's
    // stored mail.
    const ts = Date.parse(envelope.timestamp);
    if (Number.isNaN(ts)) {
      log.warn(
        `Dropped envelope ${id} from ${from} with malformed timestamp ` +
          JSON.stringify(envelope.timestamp)
      );
      return false;
    }
    const ageSeconds = Math.abs(now - ts) / 1000;
    if (
      ageSeconds > MAX_ENVELOPE_AGE &&
      !(await this._wasStored(raw, envelope.toAddress, ts, now))
    ) {
      log.info(
        `Dropped stale envelope ${id} from ${from} ` +
          `(age=${Math.round(ageSeconds)}s > ${MAX_ENVELOPE_AGE}s)`
      );
      return false;
    }

    // (c) Expiry.
    if (envelope.expires !== undefined && envelope.expires !== null) {
      const exp = Date.parse(envelope.expires);
      if (Number.isNaN(exp)) {
        log.warn(
          `Dropped envelope ${id} from ${from} with malformed expires ` +
            JSON.stringify(envelope.expires)
        );
        return false;
      }
      if (now > exp) {
        log.info(
          `Dropped expired envelope ${id} from ${from} ` +
            `(expires=${envelope.expires})`
        );
        return false;
      }
    }

    // (d) Replay: must stay last (the only check that records state).
    if (await this._replayCache.seenOrRecord(from, id, ts)) {
      log.info(`Dropped replayed envelope ${id} from ${from}`);
      return false;
    }

    return true;
  }

  /** True if a message too old to be live is stored mail, not a replay. */
  private async _wasStored(
    raw: Record<string, unknown>,
    toAddress: string,
    signedAt: number,
    now: number
  ): Promise<boolean> {
    // The signed address names our relay. _config.relayDomain may not: it can
    // be the URL's hostname, and youam.network is relay.youam.network.
    const relayDomain = toAddress.split("::").pop()!;
    if (!relayVouches(raw, signedAt, now, relayDomain)) return false;
    // The replay cache can't speak for what came before it existed.
    if (await this._replayCache.signedBeforeCache(signedAt)) return false;
    return this._relayStampsMail();
  }

  /**
   * True if our relay writes relay_meta, so a sender can't have.
   *
   * Asked only when a stale message carries a stamp. A yes is remembered for
   * good, a no for RELAY_NO_MEMORY_MS: a relay can be upgraded while this
   * agent runs. A failed lookup isn't remembered, because the relay has
   * already marked this mail delivered and the next message should get a
   * real answer.
   */
  private async _relayStampsMail(): Promise<boolean> {
    if (this._relayStamps) return true;
    if (this._monotonic() < this._relayNoUntil) return false;
    try {
      const features = await this._fetchRelayFeatures();
      this._relayStamps = features.includes(RELAY_META_FEATURE);
      if (!this._relayStamps) {
        this._relayNoUntil = this._monotonic() + RELAY_NO_MEMORY_MS;
      }
    } catch (err) {
      const reason = err instanceof Error ? err.message : String(err);
      log.warn(`Cannot read relay features: ${reason}`);
    }
    return this._relayStamps;
  }

  /** The relay's features; a body that doesn't list any is an empty list. */
  private async _fetchRelayFeatures(): Promise<unknown[]> {
    const resp = await fetch(`${this._config.relayUrl}/api/v1/versions`, {
      signal: AbortSignal.timeout(10_000),
    });
    if (!resp.ok) throw new UAMError(`Relay answered ${resp.status}`);
    const body = await resp.text();
    let data: { features?: unknown } | null;
    try {
      data = JSON.parse(body) as { features?: unknown } | null;
    } catch {
      return [];
    }
    return Array.isArray(data?.features) ? data.features : [];
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
        senderVk,
        { replyTo: msg.messageId }
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
   * Calls POST /api/v1/register with agent name and public key. If the
   * address exists (409), repeats it with a proof that this agent holds the
   * key. Stores the returned API key on disk.
   */
  private async _registerWithRelay(): Promise<void> {
    const body = {
      agent_name: this._config.name,
      public_key: serializeVerifyKey(this._keyManager.verifyKey),
    };

    let resp = await this._postRegistration(body);
    if (resp.status === 409) {
      const address = await this._addressOnRelay();
      resp = await this._postRegistration({
        ...body,
        proof: this._registrationProof(address),
      });
      if (resp.status === 409 || resp.status === 403) {
        throw this._ownershipNotProven(address);
      }
    }

    if (!resp.ok) {
      const text = await resp.text();
      throw new UAMError(
        `Registration failed: ${resp.status} ${text}`
      );
    }

    const data = (await resp.json()) as Record<string, unknown>;
    const address = data["address"] as string;
    this._useAddress(address);
    this._token = data["token"] as string;

    // Persist for the returning-user flow
    const { name } = this._config;
    const token = this._token;
    this._tryToSave("token", () => this._keyManager.saveToken(name, token));
    this._saveAddress(address);
  }

  /** This agent's address on the relay, for signing a proof. */
  private async _addressOnRelay(): Promise<string> {
    const { name, explicitRelayDomain, relayDomain, relayUrl } = this._config;
    if (explicitRelayDomain !== null) return `${name}::${explicitRelayDomain}`;

    const domain = await this._fetchRelayDomain();
    if (domain === null) return `${name}::${relayDomain}`;
    if (!this._relayMayUse(domain)) {
      throw new UAMError(
        `The relay at ${relayUrl} says its domain is ${domain}. ` +
          `Pass the domain option as ${JSON.stringify(domain)} if that is right.`
      );
    }
    return `${name}::${domain}`;
  }

  /**
   * True if the relay's URL fits `domain`, so a proof can be signed for it.
   *
   * A proof names an address on one relay, so it is only signed for a domain
   * this URL belongs to. A relay on this machine may use any domain.
   */
  private _relayMayUse(domain: string): boolean {
    let host: string;
    try {
      host = new URL(this._config.relayUrl).hostname.toLowerCase();
    } catch {
      return false;
    }
    const wanted = domain.toLowerCase();
    return (
      host === wanted ||
      host.endsWith(`.${wanted}`) ||
      host === "localhost" ||
      host === "[::1]" ||
      /^127\.\d+\.\d+\.\d+$/.test(host)
    );
  }

  private _postRegistration(body: Record<string, unknown>): Promise<Response> {
    return fetch(`${this._config.relayUrl}/api/v1/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
  }

  /**
   * Sign a statement that this agent holds the key for `address`.
   *
   * The signed string must stay byte-identical to the Python SDK's.
   */
  private _registrationProof(address: string): {
    timestamp: string;
    signature: string;
  } {
    const timestamp = utcTimestamp();
    const signature = signMessage(
      new TextEncoder().encode(`uam-register-v1\n${address}\n${timestamp}`),
      this._keyManager.signingKey
    );
    return { timestamp, signature };
  }

  private _ownershipNotProven(address: string): UAMError {
    return new UAMError(
      `Address already registered, and this key could not prove ownership: ` +
        address
    );
  }

  /** Remember `address` for this relay, if the key folder allows it. */
  private _saveAddress(address: string): void {
    const { name, relayUrl } = this._config;
    this._tryToSave("address", () =>
      this._keyManager.saveAddress(name, address, relayUrl)
    );
  }

  /** Saving is best effort: a key folder we can't write doesn't stop us. */
  private _tryToSave(what: string, save: () => void): void {
    try {
      save();
    } catch (err) {
      const reason = err instanceof Error ? err.message : String(err);
      log.warn(`Could not save the ${what}: ${reason}`);
    }
  }

  /** Take `address` as ours; its domain is this relay's real domain. */
  private _useAddress(address: string): void {
    this._address = address;
    const domain = parseAddress(address).domain;
    this._config.relayDomain = domain;
    if (this._resolver instanceof SmartResolver) {
      this._resolver.relayDomain = domain;
    }
  }

  /**
   * The address the stored token belongs to.
   *
   * An explicit domain settles it. Otherwise the relay chooses the domain,
   * and it need not be the relay's hostname: use the address saved for this
   * relay, or ask the relay once and keep the answer.
   */
  private async _storedAddress(): Promise<string> {
    const { name, explicitRelayDomain } = this._config;
    if (explicitRelayDomain !== null) return `${name}::${explicitRelayDomain}`;

    const saved = this._keyManager.loadAddress(name, this._config.relayUrl);
    if (saved) return saved;

    const domain = await this._fetchRelayDomain();
    if (domain === null) return `${name}::${this._config.relayDomain}`;
    const address = `${name}::${domain}`;
    this._saveAddress(address);
    return address;
  }

  /** Ask the relay for its domain; null if it cannot say. */
  private async _fetchRelayDomain(): Promise<string | null> {
    const url = `${this._config.relayUrl}/.well-known/uam-relay.json`;
    try {
      const resp = await fetch(url, { signal: AbortSignal.timeout(10_000) });
      if (!resp.ok) return null;
      const data = (await resp.json()) as Record<string, unknown>;
      const domain = data["relay_domain"];
      if (typeof domain !== "string" || domain === "") return null;
      // Throws, so counts as no answer, if it can't form an address.
      return parseAddress(`${this._config.name}::${domain}`).domain;
    } catch {
      return null;
    }
  }
}

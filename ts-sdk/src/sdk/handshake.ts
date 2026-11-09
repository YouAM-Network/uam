/**
 * First-contact handshake flow manager (HAND-01 through HAND-04).
 *
 * Handles the three-phase handshake:
 *   1. HANDSHAKE_REQUEST: sender sends contact card (encrypted with SealedBox)
 *   2. HANDSHAKE_ACCEPT: recipient stores contact and sends accept back
 *   3. HANDSHAKE_DENY: recipient rejects the handshake
 *
 * The HandshakeManager works with the ContactBook to persist trust decisions.
 */

import {
  MessageType,
  createEnvelope,
  createContactCard,
  verifyContactCard,
  contactCardToDict,
  contactCardFromDict,
  decryptPayload,
  decryptPayloadAnonymous,
  serializeVerifyKey,
  toWireDict,
  InvalidEnvelopeError,
  type ContactCard,
  type MessageEnvelope,
  type VerifyKey,
} from "../protocol/index.js";
import type { ContactBook } from "./contact-book.js";
import type { ReceivedMessage } from "./message.js";
import { log } from "./log.js";

// Forward reference type for Agent to avoid circular dependency
interface AgentLike {
  readonly address: string;
  readonly _config: {
    readonly displayName: string;
    readonly relayWsUrl: string;
  };
  readonly _keyManager: {
    readonly signingKey: Uint8Array;
  };
  readonly _transport: {
    send(envelope: Record<string, unknown>): Promise<unknown>;
  } | null;
}

/**
 * Check that a contact card's claimed identity is the envelope's sender.
 *
 * A card embedded in a handshake envelope must name the envelope's
 * `fromAddress` and carry the verify key that signed the envelope. Without
 * this, a sender could sign an envelope from their own address while
 * embedding a (self-consistent) card for someone else's address or key, and
 * get that identity stored in the recipient's contact book.
 *
 * `envelope` only needs `fromAddress`, so Agent.approve() can re-check a
 * stored pending entry against the address it was received from.
 *
 * Matches Python `_bind_card_to_envelope` (handshake.py).
 *
 * @throws {InvalidEnvelopeError} If the address or the key does not match.
 */
export function bindCardToEnvelope(
  card: ContactCard,
  envelope: { readonly fromAddress: string },
  senderVk: VerifyKey
): void {
  if (card.address !== envelope.fromAddress) {
    throw new InvalidEnvelopeError(
      `Contact card address ${JSON.stringify(card.address)} does not match ` +
        `envelope sender ${JSON.stringify(envelope.fromAddress)}`
    );
  }
  if (card.publicKey !== serializeVerifyKey(senderVk)) {
    throw new InvalidEnvelopeError(
      "Contact card public_key does not match envelope sender's verify key"
    );
  }
}

export class HandshakeManager {
  private _contactBook: ContactBook;
  readonly _trustPolicy: string;

  constructor(contactBook: ContactBook, trustPolicy: string) {
    this._contactBook = contactBook;
    this._trustPolicy = trustPolicy;
  }

  /**
   * Create a handshake request envelope with embedded contact card.
   *
   * The payload is the JSON-serialized contact card, encrypted with
   * SealedBox (anonymous encryption) to the recipient.
   *
   * Returns wire-format dict ready to send via transport.
   */
  async createHandshakeRequest(
    agent: AgentLike,
    toAddress: string,
    recipientVk: VerifyKey
  ): Promise<Record<string, unknown>> {
    // Create contact card for the sending agent
    const card = await createContactCard(
      agent.address,
      agent._config.displayName,
      agent._config.relayWsUrl,
      agent._keyManager.signingKey
    );
    const cardJson = JSON.stringify(contactCardToDict(card));

    // Create envelope -- createEnvelope auto-uses SealedBox for HANDSHAKE_REQUEST
    const envelope = await createEnvelope(
      agent.address,
      toAddress,
      MessageType.HANDSHAKE_REQUEST,
      new TextEncoder().encode(cardJson),
      agent._keyManager.signingKey,
      recipientVk
    );

    return toWireDict(envelope);
  }

  /**
   * Handle an inbound handshake message.
   *
   * Returns null -- handshake messages are not user-visible.
   */
  async handleInbound(
    agent: AgentLike,
    envelope: MessageEnvelope,
    senderVk: VerifyKey
  ): Promise<ReceivedMessage | null> {
    if (envelope.type === MessageType.HANDSHAKE_REQUEST) {
      await this._handleRequest(agent, envelope, senderVk);
    } else if (envelope.type === MessageType.HANDSHAKE_ACCEPT) {
      await this._handleAccept(agent, envelope, senderVk);
    } else if (envelope.type === MessageType.HANDSHAKE_DENY) {
      // Handshake denied -- logged silently
    }
    return null;
  }

  /**
   * Process a handshake.request: decrypt contact card, apply trust policy.
   */
  private async _handleRequest(
    agent: AgentLike,
    envelope: MessageEnvelope,
    senderVk: VerifyKey
  ): Promise<void> {
    // Handshake requests are encrypted with SealedBox (anonymous)
    const plaintext = decryptPayloadAnonymous(
      envelope.payload,
      agent._keyManager.signingKey
    );
    const cardDict = JSON.parse(
      new TextDecoder().decode(plaintext)
    ) as Record<string, unknown>;
    const card = contactCardFromDict(cardDict);

    // Verify the contact card's self-signature
    verifyContactCard(card);

    // Bind the card to the envelope sender before anything is stored.
    bindCardToEnvelope(card, envelope, senderVk);

    if (this._trustPolicy === "auto-accept") {
      // Store the contact as provisional (TOFU: trust upgrades on accept)
      this._contactBook.addContact(card.address, card.publicKey, {
        displayName: card.displayName,
        trustState: "provisional",
        trustSource: "auto-accepted-provisional",
      });
      // Send handshake.accept back
      await this._sendAccept(agent, envelope.fromAddress, senderVk);
    } else if (this._trustPolicy === "allowlist-only") {
      // Auto-deny: only pre-approved contacts are allowed
      await this._sendDeny(agent, envelope.fromAddress, senderVk);
    } else {
      // approval-required: store in pending for manual review
      this._contactBook.addPending(
        envelope.fromAddress,
        JSON.stringify(cardDict)
      );
    }
  }

  /**
   * Process a handshake.accept: store the sender as pinned (TOFU).
   *
   * Only honoured when:
   *   1. we previously sent this address a handshake.request
   *      (trust_state === "handshake-sent"); anything else is an unsolicited
   *      accept and is dropped. This also means an accept can never
   *      downgrade a trusted/verified contact to pinned;
   *   2. the payload decrypts with our key and the sender's key, and parses
   *      as JSON. Otherwise it is dropped without pinning;
   *   3. an embedded contact_card, if present, is well-formed, correctly
   *      self-signed, and bound to the envelope sender (throws otherwise).
   */
  private async _handleAccept(
    agent: AgentLike,
    envelope: MessageEnvelope,
    senderVk: VerifyKey
  ): Promise<void> {
    const prior = this._contactBook.getTrustState(envelope.fromAddress);
    if (prior !== "handshake-sent") {
      log.warn(
        `Ignoring unsolicited handshake.accept from ${envelope.fromAddress} ` +
          `(trust_state=${JSON.stringify(prior)})`
      );
      return;
    }

    let payload: unknown;
    try {
      const plaintext = decryptPayload(
        envelope.payload,
        agent._keyManager.signingKey,
        senderVk
      );
      payload = JSON.parse(new TextDecoder().decode(plaintext));
    } catch {
      log.warn(
        `Dropping handshake.accept ${envelope.messageId} from ` +
          `${envelope.fromAddress}: payload could not be decrypted or parsed`
      );
      return;
    }

    if (
      payload !== null &&
      typeof payload === "object" &&
      "contact_card" in payload
    ) {
      const card = contactCardFromDict(
        (payload as Record<string, unknown>)["contact_card"] as Record<
          string,
          unknown
        >
      );
      verifyContactCard(card);
      bindCardToEnvelope(card, envelope, senderVk);
    }

    const senderPkStr = serializeVerifyKey(senderVk);
    this._contactBook.addContact(envelope.fromAddress, senderPkStr, {
      trustState: "pinned",
    });
    this._contactBook.setPinnedAt(envelope.fromAddress);
  }

  /**
   * Send a handshake.accept envelope back to the requester.
   */
  async _sendAccept(
    agent: AgentLike,
    toAddress: string,
    recipientVk: VerifyKey
  ): Promise<void> {
    const card = await createContactCard(
      agent.address,
      agent._config.displayName,
      agent._config.relayWsUrl,
      agent._keyManager.signingKey
    );
    const acceptPayload = JSON.stringify({
      status: "accepted",
      contact_card: contactCardToDict(card),
    });

    const envelope = await createEnvelope(
      agent.address,
      toAddress,
      MessageType.HANDSHAKE_ACCEPT,
      new TextEncoder().encode(acceptPayload),
      agent._keyManager.signingKey,
      recipientVk
    );

    const wire = toWireDict(envelope);
    if (agent._transport) {
      await agent._transport.send(wire);
    }
  }

  /**
   * Send a handshake.deny envelope to the requester.
   */
  async _sendDeny(
    agent: AgentLike,
    toAddress: string,
    recipientVk: VerifyKey
  ): Promise<void> {
    const denyPayload = JSON.stringify({
      status: "denied",
      reason: "allowlist-only",
    });

    const envelope = await createEnvelope(
      agent.address,
      toAddress,
      MessageType.HANDSHAKE_DENY,
      new TextEncoder().encode(denyPayload),
      agent._keyManager.signingKey,
      recipientVk
    );

    const wire = toWireDict(envelope);
    if (agent._transport) {
      await agent._transport.send(wire);
    }
  }
}

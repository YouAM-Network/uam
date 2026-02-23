/**
 * UAM Protocol -- Universal Agent Messaging protocol library.
 *
 * Public API re-exports for the protocol layer.
 */

// Types
export {
  UAM_VERSION,
  MAX_ENVELOPE_SIZE,
  MessageType,
  b64Encode,
  b64Decode,
  utcTimestamp,
} from "./types.js";

// Errors
export {
  UAMError,
  InvalidAddressError,
  InvalidEnvelopeError,
  EnvelopeTooLargeError,
  SignatureError,
  SignatureVerificationError,
  EncryptionError,
  DecryptionError,
  InvalidContactCardError,
  KeyPinningError,
} from "./errors.js";

// Address
export { type Address, parseAddress } from "./address.js";

// Crypto
export {
  sodiumReady,
  type SigningKey,
  type VerifyKey,
  type Seed,
  type Keypair,
  generateKeypair,
  serializeSigningKey,
  deserializeSigningKey,
  serializeVerifyKey,
  deserializeVerifyKey,
  publicKeyFingerprint,
  canonicalize,
  signMessage,
  verifySignature,
  generateNonce,
  encryptPayload,
  decryptPayload,
  encryptPayloadAnonymous,
  decryptPayloadAnonymous,
} from "./crypto.js";

// Envelope
export {
  type MessageEnvelope,
  createEnvelope,
  verifyEnvelope,
  toWireDict,
  fromWireDict,
  validateEnvelopeSize,
} from "./envelope.js";

// Contact
export {
  type ContactCard,
  createContactCard,
  verifyContactCard,
  contactCardToDict,
  contactCardFromDict,
} from "./contact.js";

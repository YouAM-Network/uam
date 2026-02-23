/**
 * UAM exception hierarchy.
 *
 * All protocol-specific errors inherit from UAMError.
 */

/** Base error for all UAM protocol errors. */
export class UAMError extends Error {
  constructor(message?: string) {
    super(message);
    this.name = "UAMError";
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/** Raised when an address string fails validation. */
export class InvalidAddressError extends UAMError {
  constructor(message?: string) {
    super(message);
    this.name = "InvalidAddressError";
  }
}

/** Raised when an envelope fails schema validation. */
export class InvalidEnvelopeError extends UAMError {
  constructor(message?: string) {
    super(message);
    this.name = "InvalidEnvelopeError";
  }
}

/** Raised when an envelope exceeds the maximum allowed size. */
export class EnvelopeTooLargeError extends InvalidEnvelopeError {
  constructor(message?: string) {
    super(message);
    this.name = "EnvelopeTooLargeError";
  }
}

/** Raised on signing failures. */
export class SignatureError extends UAMError {
  constructor(message?: string) {
    super(message);
    this.name = "SignatureError";
  }
}

/** Raised when a cryptographic signature cannot be verified. */
export class SignatureVerificationError extends SignatureError {
  constructor(message?: string) {
    super(message);
    this.name = "SignatureVerificationError";
  }
}

/** Raised on encryption failures. */
export class EncryptionError extends UAMError {
  constructor(message?: string) {
    super(message);
    this.name = "EncryptionError";
  }
}

/** Raised on decryption failures. */
export class DecryptionError extends EncryptionError {
  constructor(message?: string) {
    super(message);
    this.name = "DecryptionError";
  }
}

/** Raised when a contact card fails validation. */
export class InvalidContactCardError extends UAMError {
  constructor(message?: string) {
    super(message);
    this.name = "InvalidContactCardError";
  }
}

/** Raised when a pinned contact's public key doesn't match the resolved key. */
export class KeyPinningError extends UAMError {
  constructor(message?: string) {
    super(message);
    this.name = "KeyPinningError";
    Object.setPrototypeOf(this, KeyPinningError.prototype);
  }
}

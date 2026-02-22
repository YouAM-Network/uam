/**
 * ReceivedMessage -- frozen data object for inbound messages.
 *
 * Matches Python message.py: a readonly interface for decrypted messages.
 * The toString() omission is deliberate prompt-injection isolation (SDK-10).
 */

/**
 * A decrypted, verified inbound message.
 *
 * This is a DATA OBJECT. Framework integrations must explicitly
 * extract .content to use in prompts. The SDK never concatenates
 * message content into LLM context automatically.
 */
export interface ReceivedMessage {
  readonly messageId: string;
  readonly fromAddress: string;
  readonly toAddress: string;
  readonly content: string;
  readonly timestamp: string;
  readonly type: string;
  readonly threadId?: string;
  readonly replyTo?: string;
  readonly mediaType?: string;
  readonly verified: boolean;
}

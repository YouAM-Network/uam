/**
 * Abstract transport interface for relay communication.
 *
 * Two implementations:
 * - HTTPTransport: stateless polling via REST API
 * - WebSocketTransport: persistent real-time connection
 */

export abstract class TransportBase {
  /** Establish connection to the relay. */
  abstract connect(): Promise<void>;

  /** Close the connection. */
  abstract disconnect(): Promise<void>;

  /** Send a message envelope to the relay. */
  abstract send(envelope: Record<string, unknown>): Promise<void>;

  /** Retrieve pending messages from the relay. */
  abstract receive(limit?: number): Promise<Record<string, unknown>[]>;

  /**
   * Start listening for real-time messages.
   *
   * For WebSocket: registers a callback for push delivery.
   * For HTTP: not supported (throws Error).
   */
  abstract listen(
    callback: (msg: Record<string, unknown>) => Promise<void>
  ): Promise<void>;
}

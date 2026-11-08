/**
 * Base class for address resolvers.
 *
 * Lives in its own module so tier3.ts can extend it without importing
 * resolver.ts (which imports tier3.ts), avoiding an import cycle.
 */

/**
 * Pluggable address resolver interface.
 */
export abstract class AddressResolver {
  /**
   * Resolve an agent address to its public key (base64).
   *
   * @throws {UAMError} If the address cannot be resolved.
   */
  abstract resolvePublicKey(
    address: string,
    token: string,
    relayUrl: string
  ): Promise<string>;
}

/**
 * SDK version, taken from package.json at build time.
 *
 * `__UAM_SDK_VERSION__` is replaced by tsup (tsup.config.ts) and defined by
 * vitest (vitest.config.ts), both from package.json's "version", so there is
 * a single place to bump it.
 */

declare const __UAM_SDK_VERSION__: string;

export const SDK_VERSION: string = __UAM_SDK_VERSION__;

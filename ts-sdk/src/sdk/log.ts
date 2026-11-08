/**
 * Minimal SDK logger.
 *
 * Mirrors the Python SDK's use of `logging`: warnings go to stderr, info
 * messages are only printed when UAM_DEBUG is set.
 */

export const log = {
  warn(message: string): void {
    console.warn(`[uam] ${message}`);
  },
  info(message: string): void {
    if (process.env["UAM_DEBUG"]) {
      console.info(`[uam] ${message}`);
    }
  },
};

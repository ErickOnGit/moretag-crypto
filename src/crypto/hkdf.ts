/**
 * HKDF (HMAC-based Key Derivation Function) using SHA-256.
 * Based on RFC 5869.
 */

import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";

/**
 * Derives cryptographic keys using HKDF with SHA-256.
 *
 * @param ikm - Input key material
 * @param salt - Salt value (should be random or pseudorandom)
 * @param info - Context and application-specific information
 * @param length - Length of output key material in bytes (must be > 0)
 * @returns Derived key material of specified length
 * @throws TypeError if length is invalid
 */
export function hkdfSha256(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  length: number
): Uint8Array {
  if (length <= 0) {
    throw new TypeError(`Invalid length: must be > 0, got ${length}`);
  }

  return hkdf(sha256, ikm, salt, info, length);
}

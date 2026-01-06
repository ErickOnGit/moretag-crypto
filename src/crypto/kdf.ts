/**
 * Domain-separated Key Derivation Functions for Double Ratchet.
 * Uses HKDF-SHA256 with explicit domain strings.
 */

import { hkdfSha256 } from "./hkdf.js";

const ENC = new TextEncoder();

function assertLen(name: string, b: Uint8Array, n: number): void {
  if (b.byteLength !== n) {
    throw new TypeError(
      `Invalid ${name} length: expected ${n} bytes, got ${b.byteLength}`
    );
  }
}

/**
 * Derives a new root key and chain key from the current root key and DH output.
 * Uses domain string "moretag/v1/rkck".
 */
export function kdfRootAndChainKey(
  rk32: Uint8Array,
  dhOut32: Uint8Array
): { rk32: Uint8Array; ck32: Uint8Array } {
  assertLen("rk32", rk32, 32);
  assertLen("dhOut32", dhOut32, 32);

  const info = ENC.encode("moretag/v1/rkck");
  const salt = rk32;
  const ikm = dhOut32;

  const derived = hkdfSha256(ikm, salt, info, 64);
  return { rk32: derived.slice(0, 32), ck32: derived.slice(32, 64) };
}

/**
 * Derives a new chain key and message key from the current chain key.
 * Uses domain string "moretag/v1/ckmk".
 */
export function kdfChainKey(ck32: Uint8Array): {
  ck32: Uint8Array;
  mk32: Uint8Array;
} {
  assertLen("ck32", ck32, 32);

  const info = ENC.encode("moretag/v1/ckmk");
  const salt = new Uint8Array(0);
  const ikm = ck32;

  const derived = hkdfSha256(ikm, salt, info, 64);
  return { ck32: derived.slice(0, 32), mk32: derived.slice(32, 64) };
}

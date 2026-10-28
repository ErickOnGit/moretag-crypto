/**
 * The Double Ratchet's KDFs (protocol v2), HKDF-SHA256 with explicit info strings.
 * KDF_RK (DR §5.2): salt = root key, input = DH output, 64 bytes split 32 root key /
 * 32 chain key. KDF_CK: input = chain key, empty salt, 64 bytes split 32 chain key /
 * 32 message key (an HKDF in place of DR §5.2's recommended HMAC).
 */

import { hkdfSha256 } from "./hkdf.js";
import { wipe } from "./wipe.js";

const ENC = new TextEncoder();

function assertLen(name: string, b: Uint8Array, n: number): void {
  if (b.byteLength !== n) {
    throw new TypeError(
      `Invalid ${name} length: expected ${n} bytes, got ${b.byteLength}`
    );
  }
}

/**
 * KDF_RK: a new root key and chain key from the current root key and a DH output.
 * Info "moretag/v2/rkck".
 */
export function kdfRootAndChainKey(
  rk32: Uint8Array,
  dhOut32: Uint8Array
): { rk32: Uint8Array; ck32: Uint8Array } {
  assertLen("rk32", rk32, 32);
  assertLen("dhOut32", dhOut32, 32);

  const info = ENC.encode("moretag/v2/rkck");
  const salt = rk32;
  const ikm = dhOut32;

  const derived = hkdfSha256(ikm, salt, info, 64);
  const out = { rk32: derived.slice(0, 32), ck32: derived.slice(32, 64) };
  wipe(derived);
  return out;
}

/**
 * KDF_CK: the next chain key and a message key from the current chain key.
 * Info "moretag/v2/ckmk".
 */
export function kdfChainKey(ck32: Uint8Array): {
  ck32: Uint8Array;
  mk32: Uint8Array;
} {
  assertLen("ck32", ck32, 32);

  const info = ENC.encode("moretag/v2/ckmk");
  const salt = new Uint8Array(0);
  const ikm = ck32;

  const derived = hkdfSha256(ikm, salt, info, 64);
  const out = { ck32: derived.slice(0, 32), mk32: derived.slice(32, 64) };
  wipe(derived);
  return out;
}

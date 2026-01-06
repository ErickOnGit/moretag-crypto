/**
 * X25519 key agreement primitives using Curve25519.
 * Uses @noble/curves for elliptic curve operations.
 */

import { x25519 } from "@noble/curves/ed25519.js";
import { randomBytes } from "@noble/ciphers/utils.js";

function clampScalar(k: Uint8Array): void {
  if (k.length !== 32) throw new TypeError("clampScalar expects 32 bytes");
  // X25519 clamping per spec: k[0]&=248; k[31]&=127; k[31]|=64
  k[0] = (k[0] ?? 0) & 248;
  k[31] = (k[31] ?? 0) & 127;
  k[31] = (k[31] ?? 0) | 64;
}

/**
 * Generates a new X25519 keypair.
 */
export function generateX25519Keypair(): {
  priv32: Uint8Array;
  pub32: Uint8Array;
} {
  const priv32 = randomBytes(32);
  clampScalar(priv32);
  const pub32 = x25519.getPublicKey(priv32);
  return { priv32, pub32 };
}

/**
 * Computes the X25519 shared secret between a private key and a public key.
 *
 * @returns 32-byte shared secret
 */
export function x25519SharedSecret(
  priv32: Uint8Array,
  pub32: Uint8Array
): Uint8Array {
  if (priv32.byteLength !== 32) {
    throw new TypeError(
      `Invalid private key length: expected 32 bytes, got ${priv32.byteLength}`
    );
  }
  if (pub32.byteLength !== 32) {
    throw new TypeError(
      `Invalid public key length: expected 32 bytes, got ${pub32.byteLength}`
    );
  }

  // Ensure private key is clamped before use (idempotent)
  const k = priv32.slice();
  clampScalar(k);

  // Normalize to exactly 32 bytes
  const ss = x25519.getSharedSecret(k, pub32);
  return ss.length === 32 ? ss : ss.slice(-32);
}

/**
 * X25519 key agreement primitives using Curve25519.
 * Backed by the active primitives provider (@noble by default; see
 * primitives.ts for the host-injection seam).
 */

import { getPrimitives } from "./primitives.js";

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
  const p = getPrimitives();
  const priv32 = p.randomBytes(32);
  clampScalar(priv32);
  const pub32 = p.x25519GetPublicKey(priv32);
  return { priv32, pub32 };
}

/**
 * Derives a public key from a private X25519 scalar.
 */
export function x25519PublicFromPrivate(priv32: Uint8Array): Uint8Array {
  if (priv32.byteLength !== 32) {
    throw new TypeError(
      `Invalid private key length: expected 32 bytes, got ${priv32.byteLength}`
    );
  }
  const k = priv32.slice();
  clampScalar(k);
  return getPrimitives().x25519GetPublicKey(k);
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

  const ss = getPrimitives().x25519SharedSecret(k, pub32);
  if (ss.byteLength !== 32) {
    throw new TypeError(
      `Invalid shared secret length: expected 32 bytes, got ${ss.byteLength}`
    );
  }
  // Low-order peer keys yield an all-zero secret. @noble and OpenSSL-family
  // backends both reject this, but each with its own error; check here so
  // every provider fails identically (RFC 7748 §6.1 MAY-check, Signal-style).
  if (ss.every((b) => b === 0)) {
    throw new Error("x25519SharedSecret: all-zero shared secret rejected");
  }
  return ss;
}

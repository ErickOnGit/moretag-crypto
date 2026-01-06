/**
 * Ed25519 signing helpers (for X3DH identity + signed prekey).
 * Uses @noble/curves.
 */
import { ed25519 } from "@noble/curves/ed25519.js";
import { randomBytes } from "@noble/ciphers/utils.js";

export function generateEd25519Keypair(): { priv32: Uint8Array; pub32: Uint8Array } {
  const priv32 = randomBytes(32);
  const pub32 = ed25519.getPublicKey(priv32);
  return { priv32, pub32 };
}

export function ed25519Sign(priv32: Uint8Array, msg: Uint8Array): Uint8Array {
  if (priv32.byteLength !== 32) {
    throw new TypeError(`Invalid Ed25519 private key length: expected 32, got ${priv32.byteLength}`);
  }
  return ed25519.sign(msg, priv32);
}

export function ed25519Verify(pub32: Uint8Array, msg: Uint8Array, sig64: Uint8Array): boolean {
  if (pub32.byteLength !== 32) {
    throw new TypeError(`Invalid Ed25519 public key length: expected 32, got ${pub32.byteLength}`);
  }
  if (sig64.byteLength !== 64) {
    throw new TypeError(`Invalid Ed25519 signature length: expected 64, got ${sig64.byteLength}`);
  }
  return ed25519.verify(sig64, msg, pub32);
}

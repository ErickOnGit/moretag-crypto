/**
 * Ed25519 signing helpers (for X3DH identity + signed prekey).
 * Backed by the active primitives provider (@noble by default; see
 * primitives.ts for the host-injection seam).
 */
import { getPrimitives } from "./primitives.js";

export function generateEd25519Keypair(): { priv32: Uint8Array; pub32: Uint8Array } {
  const p = getPrimitives();
  const priv32 = p.randomBytes(32);
  const pub32 = p.ed25519GetPublicKey(priv32);
  return { priv32, pub32 };
}

export function ed25519Sign(priv32: Uint8Array, msg: Uint8Array): Uint8Array {
  if (priv32.byteLength !== 32) {
    throw new TypeError(`Invalid Ed25519 private key length: expected 32, got ${priv32.byteLength}`);
  }
  return getPrimitives().ed25519Sign(priv32, msg);
}

export function ed25519Verify(pub32: Uint8Array, msg: Uint8Array, sig64: Uint8Array): boolean {
  if (pub32.byteLength !== 32) {
    throw new TypeError(`Invalid Ed25519 public key length: expected 32, got ${pub32.byteLength}`);
  }
  if (sig64.byteLength !== 64) {
    throw new TypeError(`Invalid Ed25519 signature length: expected 64, got ${sig64.byteLength}`);
  }
  return getPrimitives().ed25519Verify(pub32, msg, sig64);
}

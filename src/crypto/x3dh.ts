/**
 * X3DH (Extended Triple Diffie-Hellman) v1 session initialization.
 * Uses X25519 key agreement and HKDF-SHA256 for key derivation.
 *
 * This module enforces crypto invariants:
 * - base64 decode + length checks (X25519 pub 32B, Ed25519 pub 32B, Ed25519 sig 64B)
 * - signed prekey authenticity: verify SPK signature before DH
 * - requires ids needed for key management (spk_id always, opk_id iff OPK used)
 */

import { x25519 } from "@noble/curves/ed25519.js";
import { base64ToBytes, bytesToBase64 } from "../encoding/base64.js";
import { generateX25519Keypair, x25519SharedSecret } from "./x25519.js";
import { hkdfSha256 } from "./hkdf.js";
import { ed25519Verify } from "./ed25519.js";
import type { X3DHPrekeyBundleV1, X3DHSessionInitV1 } from "../wire/x3dh.js";

const ENC = new TextEncoder();

export function decodeX25519PubB64(pub_b64: string, fieldName: string): Uint8Array {
  let decoded: Uint8Array;
  try {
    decoded = base64ToBytes(pub_b64);
  } catch {
    throw new TypeError(`Invalid ${fieldName}: not valid base64`);
  }
  if (decoded.byteLength !== 32) {
    throw new TypeError(`Invalid ${fieldName} length: expected 32 bytes, got ${decoded.byteLength}`);
  }
  return decoded;
}

function decodeEd25519PubB64(pub_b64: string, fieldName: string): Uint8Array {
  let decoded: Uint8Array;
  try {
    decoded = base64ToBytes(pub_b64);
  } catch {
    throw new TypeError(`Invalid ${fieldName}: not valid base64`);
  }
  if (decoded.byteLength !== 32) {
    throw new TypeError(`Invalid ${fieldName} length: expected 32 bytes, got ${decoded.byteLength}`);
  }
  return decoded;
}

function decodeEd25519SigB64(sig_b64: string, fieldName: string): Uint8Array {
  let decoded: Uint8Array;
  try {
    decoded = base64ToBytes(sig_b64);
  } catch {
    throw new TypeError(`Invalid ${fieldName}: not valid base64`);
  }
  if (decoded.byteLength !== 64) {
    throw new TypeError(`Invalid ${fieldName} length: expected 64 bytes, got ${decoded.byteLength}`);
  }
  return decoded;
}

/**
 * Signature message (v1):
 *   "moretag/x3dh/spk/v1" || recipient_device_id || ik_pub32 || spk_pub32 || spk_id_utf8
 *
 * This binds:
 * - device id (prevents cross-device replay)
 * - X25519 identity key (binds signing identity to DH identity)
 * - SPK public key
 * - SPK identifier (binds the key lookup handle)
 */
function buildSpkSigMessage(args: {
  recipient_device_id: string;
  ik_pub32: Uint8Array;
  spk_pub32: Uint8Array;
  spk_id: number | string;
}): Uint8Array {
  const domain = ENC.encode("moretag/x3dh/spk/v1");
  const dev = ENC.encode(args.recipient_device_id);
  const spkId = ENC.encode(String(args.spk_id));

  const out = new Uint8Array(
    domain.length + dev.length + args.ik_pub32.length + args.spk_pub32.length + spkId.length
  );

  let off = 0;
  out.set(domain, off); off += domain.length;
  out.set(dev, off); off += dev.length;
  out.set(args.ik_pub32, off); off += args.ik_pub32.length;
  out.set(args.spk_pub32, off); off += args.spk_pub32.length;
  out.set(spkId, off);

  return out;
}

export function x3dhInitiatorV1(args: {
  sender_device_id: string;
  recipient_bundle: X3DHPrekeyBundleV1;
  initiator_ik_priv32: Uint8Array;
  initiator_ek_priv32?: Uint8Array;
}): { session_init: X3DHSessionInitV1; rk32: Uint8Array } {
  const { sender_device_id, recipient_bundle, initiator_ik_priv32 } = args;

  if (initiator_ik_priv32.byteLength !== 32) {
    throw new TypeError(
      `Invalid initiator_ik_priv32 length: expected 32 bytes, got ${initiator_ik_priv32.byteLength}`
    );
  }

  // Ephemeral key (generate if not provided)
  let ek_priv32: Uint8Array;
  let ek_pub32: Uint8Array;
  if (args.initiator_ek_priv32) {
    if (args.initiator_ek_priv32.byteLength !== 32) {
      throw new TypeError(
        `Invalid initiator_ek_priv32 length: expected 32 bytes, got ${args.initiator_ek_priv32.byteLength}`
      );
    }
    ek_priv32 = args.initiator_ek_priv32;
    ek_pub32 = x25519.getPublicKey(ek_priv32);
  } else {
    const kp = generateX25519Keypair();
    ek_priv32 = kp.priv32;
    ek_pub32 = kp.pub32;
  }

  const ik_a_pub32 = x25519.getPublicKey(initiator_ik_priv32);

  // Decode recipient bundle fields
  const ik_b_pub32 = decodeX25519PubB64(recipient_bundle.ik_pub_b64, "ik_pub_b64");
  const spk_b_pub32 = decodeX25519PubB64(recipient_bundle.spk_pub_b64, "spk_pub_b64");
  const ik_sig_pub32 = decodeEd25519PubB64(recipient_bundle.ik_sig_pub_b64, "ik_sig_pub_b64");
  const spk_sig64 = decodeEd25519SigB64(recipient_bundle.spk_sig_b64, "spk_sig_b64");

  // Verify SPK signature BEFORE DH
  const sigMsg = buildSpkSigMessage({
    recipient_device_id: recipient_bundle.recipient_device_id,
    ik_pub32: ik_b_pub32,
    spk_pub32: spk_b_pub32,
    spk_id: recipient_bundle.spk_id,
  });

  if (!ed25519Verify(ik_sig_pub32, sigMsg, spk_sig64)) {
    throw new TypeError("Invalid spk_sig_b64: signature verification failed");
  }

  // Optional OPK
  let opk_b_pub32: Uint8Array | undefined;
  if (recipient_bundle.opk_pub_b64 !== undefined) {
    // wire validator requires opk_id when opk_pub_b64 is present; enforce anyway
    if (recipient_bundle.opk_id === undefined) {
      throw new TypeError("opk_id is required when opk_pub_b64 is provided");
    }
    opk_b_pub32 = decodeX25519PubB64(recipient_bundle.opk_pub_b64, "opk_pub_b64");
  }

  // DH order:
  const dh1 = x25519SharedSecret(initiator_ik_priv32, spk_b_pub32);
  const dh2 = x25519SharedSecret(ek_priv32, ik_b_pub32);
  const dh3 = x25519SharedSecret(ek_priv32, spk_b_pub32);

  let dhConcatenated: Uint8Array;
  if (opk_b_pub32) {
    const dh4 = x25519SharedSecret(ek_priv32, opk_b_pub32);
    dhConcatenated = new Uint8Array(128);
    dhConcatenated.set(dh1, 0);
    dhConcatenated.set(dh2, 32);
    dhConcatenated.set(dh3, 64);
    dhConcatenated.set(dh4, 96);
  } else {
    dhConcatenated = new Uint8Array(96);
    dhConcatenated.set(dh1, 0);
    dhConcatenated.set(dh2, 32);
    dhConcatenated.set(dh3, 64);
  }

  // Root key derivation
  const salt = new Uint8Array(32);
  const info = ENC.encode("moretag/x3dh/v1");
  const rk32 = hkdfSha256(dhConcatenated, salt, info, 32);

  // Session init message (include ids)
  const session_init: X3DHSessionInitV1 = {
    v: 1,
    alg: "x3dh-x25519-hkdf-sha256+ed25519",
    sender_device_id,
    sender_ik_pub_b64: bytesToBase64(ik_a_pub32),
    ek_pub_b64: bytesToBase64(ek_pub32),
    recipient_device_id: recipient_bundle.recipient_device_id,
    spk_id: recipient_bundle.spk_id,
    used_opk: !!opk_b_pub32,
    ...(opk_b_pub32 ? { opk_id: recipient_bundle.opk_id } : {}),
  };

  return { session_init, rk32 };
}

export function x3dhResponderV1(args: {
  session_init: X3DHSessionInitV1;
  recipient_ik_priv32: Uint8Array;
  recipient_spk_priv32: Uint8Array;
  recipient_opk_priv32?: Uint8Array;
}): { rk32: Uint8Array } {
  const {
    session_init,
    recipient_ik_priv32,
    recipient_spk_priv32,
    recipient_opk_priv32,
  } = args;

  if (recipient_ik_priv32.byteLength !== 32) {
    throw new TypeError(
      `Invalid recipient_ik_priv32 length: expected 32 bytes, got ${recipient_ik_priv32.byteLength}`
    );
  }
  if (recipient_spk_priv32.byteLength !== 32) {
    throw new TypeError(
      `Invalid recipient_spk_priv32 length: expected 32 bytes, got ${recipient_spk_priv32.byteLength}`
    );
  }

  if (session_init.used_opk) {
    if (session_init.opk_id === undefined) {
      throw new TypeError("opk_id is required in session_init when used_opk is true");
    }
    if (!recipient_opk_priv32) {
      throw new TypeError("recipient_opk_priv32 is required when used_opk is true");
    }
    if (recipient_opk_priv32.byteLength !== 32) {
      throw new TypeError(
        `Invalid recipient_opk_priv32 length: expected 32 bytes, got ${recipient_opk_priv32.byteLength}`
      );
    }
  }

  // Decode initiator public keys
  const ik_a_pub32 = decodeX25519PubB64(session_init.sender_ik_pub_b64, "sender_ik_pub_b64");
  const ek_a_pub32 = decodeX25519PubB64(session_init.ek_pub_b64, "ek_pub_b64");

  // DH order mirrors initiator concatenation
  const dh1 = x25519SharedSecret(recipient_spk_priv32, ik_a_pub32);
  const dh2 = x25519SharedSecret(recipient_ik_priv32, ek_a_pub32);
  const dh3 = x25519SharedSecret(recipient_spk_priv32, ek_a_pub32);

  let dhConcatenated: Uint8Array;
  if (session_init.used_opk && recipient_opk_priv32) {
    const dh4 = x25519SharedSecret(recipient_opk_priv32, ek_a_pub32);
    dhConcatenated = new Uint8Array(128);
    dhConcatenated.set(dh1, 0);
    dhConcatenated.set(dh2, 32);
    dhConcatenated.set(dh3, 64);
    dhConcatenated.set(dh4, 96);
  } else {
    dhConcatenated = new Uint8Array(96);
    dhConcatenated.set(dh1, 0);
    dhConcatenated.set(dh2, 32);
    dhConcatenated.set(dh3, 64);
  }

  const salt = new Uint8Array(32);
  const info = ENC.encode("moretag/x3dh/v1");
  const rk32 = hkdfSha256(dhConcatenated, salt, info, 32);

  return { rk32 };
}

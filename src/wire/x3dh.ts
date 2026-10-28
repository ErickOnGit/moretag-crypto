/**
 * X3DH wire objects (protocol v2) and their validators.
 *
 * The validators check everything a peer or a server controls before any key is
 * used: version and algorithm, canonical device ids, strict base64 with exact
 * decoded lengths, ids in 1..2^31-1, and the one-time prekey invariants. A refusal
 * is {@link InvalidDeviceIdError} for a non-canonical device id and
 * {@link InvalidWireError} (`invalid_bundle`, `invalid_session_init`) otherwise.
 * The signature itself is checked in crypto/x3dh.ts.
 */

import { InvalidWireError, type InvalidWireCode } from "../errors.js";
import { decodeStrictBase64 } from "../encoding/base64.js";
import { assertCanonicalDeviceId } from "../crypto/device-id.js";

export const X3DH_ALG_V2 = "x3dh-x25519-hkdf-sha256+ed25519" as const;

/** Largest prekey id: ids are 1..2^31-1, so they fit a Postgres integer. */
export const MAX_PREKEY_ID = 2 ** 31 - 1;

export function isPrekeyId(v: unknown): v is number {
  return typeof v === "number" && Number.isSafeInteger(v) && v >= 1 && v <= MAX_PREKEY_ID;
}

/**
 * A device's prekey bundle, as the server serves it. The one-time prekey is
 * optional: present when the server allocated one, absent when the pool was empty
 * or a limit was reached (the fallback, X3DH §3.3 without DH4).
 */
export interface X3DHPrekeyBundleV2 {
  v: 2;
  alg: typeof X3DH_ALG_V2;
  recipient_device_id: string;
  /** X25519 identity key (32 bytes). */
  ik_pub_b64: string;
  /** Ed25519 identity signing key (32 bytes). */
  ik_sig_pub_b64: string;
  /** X25519 signed prekey (32 bytes) and its id. */
  spk_pub_b64: string;
  spk_id: number;
  /** Ed25519 signature (64 bytes) over the signed-prekey message. */
  spk_sig_b64: string;
  /** The device's local one-time prekey id and key, together or not at all. */
  opk_id?: number;
  opk_pub_b64?: string;
}

/**
 * The initiator's setup sidecar. It travels in the clear beside the first
 * messages; every security-relevant field is bound once a message on the session
 * decrypts: the EK and prekey ids through SK, the keys and device ids through AD.
 */
export interface X3DHSessionInitV2 {
  v: 2;
  alg: typeof X3DH_ALG_V2;
  sender_device_id: string;
  recipient_device_id: string;
  /** X25519 identity key of the initiator (32 bytes). */
  sender_ik_pub_b64: string;
  /** Ed25519 identity signing key of the initiator (32 bytes), required. */
  sender_ik_sig_pub_b64: string;
  /** X25519 ephemeral key (32 bytes). */
  ek_pub_b64: string;
  spk_id: number;
  used_opk: boolean;
  /** Present exactly when used_opk is true. */
  opk_id?: number;
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function bytes(code: InvalidWireCode, field: string, value: unknown, length: number): Uint8Array {
  if (typeof value !== "string") throw new InvalidWireError(code, field);
  let out: Uint8Array;
  try {
    out = decodeStrictBase64(field, value);
  } catch {
    throw new InvalidWireError(code, field);
  }
  if (out.byteLength !== length) throw new InvalidWireError(code, field);
  return out;
}

/** A bundle's fields, decoded and checked (the signature not yet verified). */
export interface DecodedPrekeyBundleV2 {
  recipient_device_id: string;
  ik_pub32: Uint8Array;
  ik_sig_pub32: Uint8Array;
  spk_pub32: Uint8Array;
  spk_id: number;
  spk_sig64: Uint8Array;
  opk?: { opk_id: number; pub32: Uint8Array };
}

export function decodePrekeyBundleV2(x: unknown): DecodedPrekeyBundleV2 {
  const c = "invalid_bundle";
  if (!isPlainObject(x)) throw new InvalidWireError(c, "bundle");
  if (x.v !== 2) throw new InvalidWireError(c, "v");
  if (x.alg !== X3DH_ALG_V2) throw new InvalidWireError(c, "alg");
  assertCanonicalDeviceId(x.recipient_device_id);
  const out: DecodedPrekeyBundleV2 = {
    recipient_device_id: x.recipient_device_id,
    ik_pub32: bytes(c, "ik_pub_b64", x.ik_pub_b64, 32),
    ik_sig_pub32: bytes(c, "ik_sig_pub_b64", x.ik_sig_pub_b64, 32),
    spk_pub32: bytes(c, "spk_pub_b64", x.spk_pub_b64, 32),
    spk_id: 0,
    spk_sig64: bytes(c, "spk_sig_b64", x.spk_sig_b64, 64),
  };
  if (!isPrekeyId(x.spk_id)) throw new InvalidWireError(c, "spk_id");
  out.spk_id = x.spk_id;
  const hasId = x.opk_id !== undefined;
  const hasKey = x.opk_pub_b64 !== undefined;
  if (hasId !== hasKey) throw new InvalidWireError(c, "opk_id and opk_pub_b64 go together");
  if (hasId) {
    if (!isPrekeyId(x.opk_id)) throw new InvalidWireError(c, "opk_id");
    out.opk = { opk_id: x.opk_id, pub32: bytes(c, "opk_pub_b64", x.opk_pub_b64, 32) };
  }
  return out;
}

/** Runtime validator for {@link X3DHPrekeyBundleV2}; see {@link decodePrekeyBundleV2}. */
export function assertX3DHPrekeyBundleV2(x: unknown): asserts x is X3DHPrekeyBundleV2 {
  decodePrekeyBundleV2(x);
}

/** A session_init's fields, decoded and checked. */
export interface DecodedSessionInitV2 {
  sender_device_id: string;
  recipient_device_id: string;
  sender_ik_pub32: Uint8Array;
  sender_ik_sig_pub32: Uint8Array;
  ek_pub32: Uint8Array;
  spk_id: number;
  opk_id?: number;
}

export function decodeSessionInitV2(x: unknown): DecodedSessionInitV2 {
  const c = "invalid_session_init";
  if (!isPlainObject(x)) throw new InvalidWireError(c, "session_init");
  if (x.v !== 2) throw new InvalidWireError(c, "v");
  if (x.alg !== X3DH_ALG_V2) throw new InvalidWireError(c, "alg");
  assertCanonicalDeviceId(x.sender_device_id);
  assertCanonicalDeviceId(x.recipient_device_id);
  const out: DecodedSessionInitV2 = {
    sender_device_id: x.sender_device_id,
    recipient_device_id: x.recipient_device_id,
    sender_ik_pub32: bytes(c, "sender_ik_pub_b64", x.sender_ik_pub_b64, 32),
    sender_ik_sig_pub32: bytes(c, "sender_ik_sig_pub_b64", x.sender_ik_sig_pub_b64, 32),
    ek_pub32: bytes(c, "ek_pub_b64", x.ek_pub_b64, 32),
    spk_id: 0,
  };
  if (!isPrekeyId(x.spk_id)) throw new InvalidWireError(c, "spk_id");
  out.spk_id = x.spk_id;
  if (typeof x.used_opk !== "boolean") throw new InvalidWireError(c, "used_opk");
  if (x.used_opk !== (x.opk_id !== undefined)) {
    throw new InvalidWireError(c, "opk_id present exactly when used_opk");
  }
  if (x.used_opk) {
    if (!isPrekeyId(x.opk_id)) throw new InvalidWireError(c, "opk_id");
    out.opk_id = x.opk_id;
  }
  return out;
}

/** Runtime validator for {@link X3DHSessionInitV2}; see {@link decodeSessionInitV2}. */
export function assertX3DHSessionInitV2(x: unknown): asserts x is X3DHSessionInitV2 {
  decodeSessionInitV2(x);
}

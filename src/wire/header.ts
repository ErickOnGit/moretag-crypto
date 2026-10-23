/**
 * The message header (protocol v2), a JSON object on the wire.
 *
 * The header is not the AAD: the bytes that enter the AEAD are AD || H, where H is
 * a shortest-form CBOR array built from the header's decoded fields (see
 * crypto/aad.ts). Keys other than the ones below, such as a host's session_init
 * sidecar, may ride in the same JSON object and never enter H.
 */

import { InvalidWireError } from "../errors.js";
import { decodeStrictBase64 } from "../encoding/base64.js";
import { assertCanonicalDeviceId, isCanonicalDeviceId } from "../crypto/device-id.js";
import { MAX_CIPHERTEXT_BYTES } from "../crypto/limits.js";

/** Double Ratchet header fields (DR §3.1): the sender's ratchet key and counters. */
export interface DoubleRatchetHeader {
  /** Base64 of the sender's current ratchet public key (32 bytes). */
  dh_pub_b64: string;
  /** Number of messages in the sender's previous sending chain. */
  pn: number;
  /** Message number in the current sending chain. */
  n: number;
}

/**
 * The group slot: a group id and membership epoch, authenticated in H. Pairwise
 * messages leave it out (H carries null). The library checks only its shape; the
 * host's duty, once groups exist, is to check `gid` against the conversation and
 * `epoch` against the server's membership epoch.
 */
export interface GroupSlotV2 {
  /** Canonical lowercase UUID of the group. */
  gid: string;
  /** Membership epoch, a safe integer >= 0. */
  epoch: number;
}

export interface HeaderProtoV2 {
  v: 2;
  alg: "xchacha20poly1305";
  /** Base64 of the random 24-byte XChaCha20-Poly1305 nonce. */
  nonce_b64: string;
  /** Canonical UUID of the sending device (the session's own id for its role). */
  sender_device_id: string;
  /** Canonical UUID of the receiving device. */
  recipient_device_id: string;
  dr: DoubleRatchetHeader;
  /** Present only on a group message. */
  grp?: GroupSlotV2;
}

/** A header's fields, decoded and checked. */
export interface DecodedHeaderV2 {
  nonce24: Uint8Array;
  sender_device_id: string;
  recipient_device_id: string;
  dh_pub32: Uint8Array;
  pn: number;
  n: number;
  grp: GroupSlotV2 | null;
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function isCounter(v: unknown): v is number {
  return typeof v === "number" && Number.isSafeInteger(v) && v >= 0;
}

function bytesOf(field: string, value: unknown, length: number): Uint8Array {
  if (typeof value !== "string") throw new InvalidWireError("invalid_header", field);
  let bytes: Uint8Array;
  try {
    bytes = decodeStrictBase64(field, value);
  } catch {
    throw new InvalidWireError("invalid_header", field);
  }
  if (bytes.byteLength !== length) throw new InvalidWireError("invalid_header", field);
  return bytes;
}

/**
 * Checks a group slot: absent (or null) means a pairwise message. Otherwise an
 * object with a canonical UUID `gid` and a safe integer `epoch` >= 0, else
 * {@link InvalidWireError} `invalid_grp`.
 */
export function decodeGroupSlotV2(grp: unknown): GroupSlotV2 | null {
  if (grp === undefined || grp === null) return null;
  if (!isPlainObject(grp)) throw new InvalidWireError("invalid_grp", "grp");
  if (!isCanonicalDeviceId(grp.gid)) throw new InvalidWireError("invalid_grp", "grp.gid");
  if (!isCounter(grp.epoch)) throw new InvalidWireError("invalid_grp", "grp.epoch");
  return { gid: grp.gid, epoch: grp.epoch };
}

/**
 * Decodes and checks a v2 header: version, algorithm, strict base64 with exact
 * lengths (nonce 24, dh_pub 32), canonical device ids, non-negative safe-integer
 * counters and the group slot. Throws {@link InvalidWireError} (`invalid_header`,
 * `invalid_grp`) or {@link InvalidDeviceIdError}.
 */
export function decodeHeaderV2(x: unknown): DecodedHeaderV2 {
  if (!isPlainObject(x)) throw new InvalidWireError("invalid_header", "header");
  if (x.v !== 2) throw new InvalidWireError("invalid_header", "v");
  if (x.alg !== "xchacha20poly1305") throw new InvalidWireError("invalid_header", "alg");
  const nonce24 = bytesOf("nonce_b64", x.nonce_b64, 24);
  assertCanonicalDeviceId(x.sender_device_id);
  assertCanonicalDeviceId(x.recipient_device_id);
  if (!isPlainObject(x.dr)) throw new InvalidWireError("invalid_header", "dr");
  const dh_pub32 = bytesOf("dr.dh_pub_b64", x.dr.dh_pub_b64, 32);
  if (!isCounter(x.dr.pn)) throw new InvalidWireError("invalid_header", "dr.pn");
  if (!isCounter(x.dr.n)) throw new InvalidWireError("invalid_header", "dr.n");
  const grp = decodeGroupSlotV2(x.grp);
  return {
    nonce24,
    sender_device_id: x.sender_device_id,
    recipient_device_id: x.recipient_device_id,
    dh_pub32,
    pn: x.dr.pn,
    n: x.dr.n,
    grp,
  };
}

/**
 * Decodes a message's `ciphertext_b64`, the field beside its header: strict
 * base64, at most MAX_CIPHERTEXT_BYTES decoded, else {@link InvalidWireError}
 * `invalid_header` naming `ciphertext_b64`. An over-long string is refused
 * before it is decoded.
 */
export function decodeCiphertextV2(ciphertext_b64: unknown): Uint8Array {
  const field = "ciphertext_b64";
  if (typeof ciphertext_b64 !== "string" || ciphertext_b64.length > Math.ceil(MAX_CIPHERTEXT_BYTES / 3) * 4) {
    throw new InvalidWireError("invalid_header", field);
  }
  let ciphertext: Uint8Array;
  try {
    ciphertext = decodeStrictBase64(field, ciphertext_b64);
  } catch {
    throw new InvalidWireError("invalid_header", field);
  }
  if (ciphertext.byteLength > MAX_CIPHERTEXT_BYTES) throw new InvalidWireError("invalid_header", field);
  return ciphertext;
}

/** Runtime validator for {@link HeaderProtoV2}; see {@link decodeHeaderV2}. */
export function assertHeaderProtoV2(x: unknown): asserts x is HeaderProtoV2 {
  decodeHeaderV2(x);
}

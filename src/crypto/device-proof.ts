/**
 * The device proof and the pairing code (docs/SPEC.md §4.5).
 *
 *   proof = Ed25519(acting IKsig) over CBOR ["moretag/device-proof/v1", action,
 *           acting_device_id, session_id, issued_at_s, target_device_id | "",
 *           target_ik_sig_pub (bstr 32, approve only) | h'']
 *   code  = uint32_be(SHA-256("moretag/device-code/v1" || IKsig)[0..4]) mod 10^6
 *
 * The server mirrors both byte for byte; vectors/device-proof-v1.json and
 * vectors/device-code-v1.json pin them.
 */

import { sha256 } from "@noble/hashes/sha2.js";
import { encodeCbor } from "../encoding/cbor.js";
import { assertCanonicalDeviceId, isCanonicalDeviceId } from "./device-id.js";
import { ed25519Verify } from "./ed25519.js";

/** Domain string of the device proof. */
export const DEVICE_PROOF_DOMAIN = "moretag/device-proof/v1";
/** Domain string hashed with the key for the pairing code. */
export const DEVICE_CODE_DOMAIN = "moretag/device-code/v1";
/** A proof verifies while the verifier's clock is within this many seconds of `issued_at_s`. */
export const DEVICE_PROOF_MAX_SKEW_S = 300;

export type DeviceProofAction = "approve" | "remove" | "reset" | "refresh";

const TARGETED: Readonly<Record<DeviceProofAction, boolean>> = Object.freeze({
  approve: true,
  remove: true,
  reset: false,
  refresh: false,
});

/**
 * What a proof says. `target_device_id` is given for approve and remove only;
 * `target_ik_sig_pub32` (the target's Ed25519 key) for approve only. Where a field
 * is not given, its wire value ("" or an empty byte array) means the same.
 */
export interface DeviceProofFields {
  action: DeviceProofAction;
  acting_device_id: string;
  session_id: string;
  issued_at_s: number;
  target_device_id?: string | undefined;
  target_ik_sig_pub32?: Uint8Array | undefined;
}

const ENC = new TextEncoder();
const CODE_DOMAIN_BYTES = ENC.encode(DEVICE_CODE_DOMAIN);
const EMPTY: Uint8Array = new Uint8Array(0);

function isAction(value: unknown): value is DeviceProofAction {
  return typeof value === "string" && Object.prototype.hasOwnProperty.call(TARGETED, value);
}

function isSecondsTime(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

/**
 * The message a device proof signs (SPEC §4.5). Refuses any input outside the
 * spec: a non-canonical device id is `invalid_device_id`, anything else a TypeError.
 */
export function buildDeviceProofMessage(fields: DeviceProofFields): Uint8Array {
  const { action, acting_device_id, session_id, issued_at_s, target_device_id, target_ik_sig_pub32 } = fields;
  if (!isAction(action)) throw new TypeError("Unknown device proof action");
  assertCanonicalDeviceId(acting_device_id);
  if (!isCanonicalDeviceId(session_id)) throw new TypeError("session_id must be a canonical UUID");
  if (!isSecondsTime(issued_at_s)) throw new TypeError("issued_at_s must be a safe integer >= 0");

  let target = "";
  let targetKey: Uint8Array = EMPTY;
  if (TARGETED[action]) {
    if (target_device_id === undefined) throw new TypeError(`A ${action} proof needs target_device_id`);
    assertCanonicalDeviceId(target_device_id);
    target = target_device_id;
  } else if (target_device_id !== undefined && target_device_id !== "") {
    throw new TypeError(`A ${action} proof takes no target_device_id`);
  }
  if (action === "approve") {
    if (target === acting_device_id) throw new TypeError("A device cannot approve itself");
    if (!(target_ik_sig_pub32 instanceof Uint8Array) || target_ik_sig_pub32.byteLength !== 32) {
      throw new TypeError("An approve proof needs the target's 32-byte signing key");
    }
    targetKey = target_ik_sig_pub32;
  } else if (target_ik_sig_pub32 !== undefined && !(target_ik_sig_pub32 instanceof Uint8Array && target_ik_sig_pub32.byteLength === 0)) {
    throw new TypeError(`A ${action} proof takes no target key`);
  }

  return encodeCbor([DEVICE_PROOF_DOMAIN, action, acting_device_id, session_id, issued_at_s, target, targetKey]);
}

export type DeviceProofVerdict = "valid" | "bad_signature" | "expired";

/**
 * Checks a proof against the verifier's own facts: the fields as the server knows
 * them (the session id from the verified JWT), the acting device's stored key and
 * the verifier's clock in whole seconds. The signature first, so `expired` is said
 * only of an authentic proof. A signature of the wrong length is `bad_signature`;
 * fields outside the spec throw as in {@link buildDeviceProofMessage}.
 */
export function verifyDeviceProof(args: {
  fields: DeviceProofFields;
  acting_ik_sig_pub32: Uint8Array;
  proof_sig64: Uint8Array;
  now_s: number;
}): DeviceProofVerdict {
  const message = buildDeviceProofMessage(args.fields);
  if (!(args.acting_ik_sig_pub32 instanceof Uint8Array) || args.acting_ik_sig_pub32.byteLength !== 32) {
    throw new TypeError("acting_ik_sig_pub32 must be 32 bytes");
  }
  if (!isSecondsTime(args.now_s)) throw new TypeError("now_s must be a safe integer >= 0");
  if (!(args.proof_sig64 instanceof Uint8Array) || args.proof_sig64.byteLength !== 64) return "bad_signature";
  if (!ed25519Verify(args.acting_ik_sig_pub32, message, args.proof_sig64)) return "bad_signature";
  return Math.abs(args.now_s - args.fields.issued_at_s) > DEVICE_PROOF_MAX_SKEW_S ? "expired" : "valid";
}

/**
 * The six-digit pairing code of a device's Ed25519 identity signing key, with
 * leading zeros ("048213"). A selector, not a secret (SPEC §4.5).
 */
export function deviceCode(ik_sig_pub32: Uint8Array): string {
  if (!(ik_sig_pub32 instanceof Uint8Array) || ik_sig_pub32.byteLength !== 32) {
    throw new TypeError("ik_sig_pub32 must be 32 bytes");
  }
  const input = new Uint8Array(CODE_DOMAIN_BYTES.length + 32);
  input.set(CODE_DOMAIN_BYTES, 0);
  input.set(ik_sig_pub32, CODE_DOMAIN_BYTES.length);
  const d = sha256(input);
  const n = ((d[0]! << 24) | (d[1]! << 16) | (d[2]! << 8) | d[3]!) >>> 0;
  return String(n % 1_000_000).padStart(6, "0");
}

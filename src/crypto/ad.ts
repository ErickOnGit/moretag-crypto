/**
 * The session's associated data, AD (protocol v2).
 *
 * Built once at bootstrap from decoded bytes; A is the initiator and B the
 * responder for the whole session, in both directions:
 *
 *   AD = 0x05 || IK_A (33) || 0x05 || IK_B (33)
 *     || 0xED || IKsig_A (33) || 0xED || IKsig_B (33)
 *     || dev_A (16) || dev_B (16)                      = 164 bytes
 *
 * The first 66 bytes are X3DH §3.3's Encode(IK_A) || Encode(IK_B), with 0x05 as
 * the curve-type byte (X3DH §2.1). The Ed25519 keys and device ids are the
 * "additional information" §3.3 allows to be appended: no DH covers the Ed25519
 * keys, and the device ids stop a valid setup being relabelled as another device.
 * The length is fixed, so CONCAT(AD, H) needs no length prefix (DR §3.1).
 */

import { SelfSessionError } from "../errors.js";
import { assertCanonicalDeviceId, deviceIdFromBytes, deviceIdToBytes } from "./device-id.js";
import { timingSafeEqual } from "./validation.js";

export const ASSOCIATED_DATA_V2_LENGTH = 164;

const IK_TYPE = 0x05;
const IK_SIG_TYPE = 0xed;

export interface AssociatedDataV2 {
  initiator_ik_pub32: Uint8Array;
  responder_ik_pub32: Uint8Array;
  initiator_ik_sig_pub32: Uint8Array;
  responder_ik_sig_pub32: Uint8Array;
  initiator_device_id: string;
  responder_device_id: string;
}

function key32(label: string, key: Uint8Array): Uint8Array {
  if (!(key instanceof Uint8Array) || key.byteLength !== 32) {
    throw new TypeError(`Invalid ${label} length: expected 32 bytes`);
  }
  return key;
}

/**
 * Builds the 164-byte AD. Throws {@link InvalidDeviceIdError} for a non-canonical
 * device id and {@link SelfSessionError} when both device ids are equal.
 */
export function buildAssociatedDataV2(parts: AssociatedDataV2): Uint8Array {
  assertCanonicalDeviceId(parts.initiator_device_id);
  assertCanonicalDeviceId(parts.responder_device_id);
  const devA = deviceIdToBytes(parts.initiator_device_id);
  const devB = deviceIdToBytes(parts.responder_device_id);
  if (timingSafeEqual(devA, devB)) throw new SelfSessionError();

  const ad = new Uint8Array(ASSOCIATED_DATA_V2_LENGTH);
  ad[0] = IK_TYPE;
  ad.set(key32("initiator_ik_pub32", parts.initiator_ik_pub32), 1);
  ad[33] = IK_TYPE;
  ad.set(key32("responder_ik_pub32", parts.responder_ik_pub32), 34);
  ad[66] = IK_SIG_TYPE;
  ad.set(key32("initiator_ik_sig_pub32", parts.initiator_ik_sig_pub32), 67);
  ad[99] = IK_SIG_TYPE;
  ad.set(key32("responder_ik_sig_pub32", parts.responder_ik_sig_pub32), 100);
  ad.set(devA, 132);
  ad.set(devB, 148);
  return ad;
}

/**
 * Splits a 164-byte AD into its parts (copies). Throws TypeError when the length or
 * a type byte is wrong, and {@link SelfSessionError} when both device ids are equal.
 */
export function parseAssociatedDataV2(ad: Uint8Array): AssociatedDataV2 {
  if (
    !(ad instanceof Uint8Array) ||
    ad.byteLength !== ASSOCIATED_DATA_V2_LENGTH ||
    ad[0] !== IK_TYPE ||
    ad[33] !== IK_TYPE ||
    ad[66] !== IK_SIG_TYPE ||
    ad[99] !== IK_SIG_TYPE
  ) {
    throw new TypeError("Invalid associated data");
  }
  const devA = ad.slice(132, 148);
  const devB = ad.slice(148, 164);
  if (timingSafeEqual(devA, devB)) throw new SelfSessionError();
  return {
    initiator_ik_pub32: ad.slice(1, 33),
    responder_ik_pub32: ad.slice(34, 66),
    initiator_ik_sig_pub32: ad.slice(67, 99),
    responder_ik_sig_pub32: ad.slice(100, 132),
    initiator_device_id: deviceIdFromBytes(devA),
    responder_device_id: deviceIdFromBytes(devB),
  };
}

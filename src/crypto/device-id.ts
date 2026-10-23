/**
 * Device ids in protocol v2 are canonical UUID strings: lowercase hex in the
 * 8-4-4-4-12 layout, as Postgres prints a `uuid`. Every v2 validator (header,
 * session_init, prekey bundle, associated data) refuses anything else with
 * {@link InvalidDeviceIdError}. The version and variant bits are not checked: a
 * Postgres uuid may carry any version. Inside the associated data and the header
 * array H a device id is its 16 raw bytes.
 */

import { InvalidDeviceIdError } from "../errors.js";

const CANONICAL_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export function isCanonicalDeviceId(value: unknown): value is string {
  return typeof value === "string" && CANONICAL_UUID.test(value);
}

/** Throws {@link InvalidDeviceIdError} unless `value` is a canonical lowercase UUID. */
export function assertCanonicalDeviceId(value: unknown): asserts value is string {
  if (!isCanonicalDeviceId(value)) throw new InvalidDeviceIdError();
}

/** The 16 raw bytes of a canonical device id. */
export function deviceIdToBytes(deviceId: string): Uint8Array {
  assertCanonicalDeviceId(deviceId);
  const hex = deviceId.replace(/-/g, "");
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) out[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  return out;
}

/** The canonical string for 16 raw bytes. */
export function deviceIdFromBytes(bytes: Uint8Array): string {
  if (bytes.byteLength !== 16) throw new TypeError("A device id is 16 bytes");
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

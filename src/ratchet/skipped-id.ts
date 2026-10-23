/**
 * Skipped message keys are stored under `${base64(32-byte DH public key)}:${message number}`.
 * The ratchet builds these ids; the deserializers accept only ids in this grammar, since
 * anything else can never match an incoming message and only takes up space.
 */

import { bytesToBase64 } from "../encoding/base64.js";

// Canonical base64 of 32 bytes: 43 characters and "=", the last character's two
// unused bits zero (so one of AEIMQUYcgkosw048); then ":" and n in shortest decimal.
const SKIPPED_KEY_ID = /^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=:(0|[1-9][0-9]{0,15})$/;

/** True when `id` is in the grammar above and n is a safe integer (at most 2^53 - 1). */
export function isSkippedKeyId(id: unknown): id is string {
  if (typeof id !== "string") return false;
  const m = SKIPPED_KEY_ID.exec(id);
  return m !== null && Number(m[1]) <= Number.MAX_SAFE_INTEGER;
}

export function skippedKeyId(dhPub32: Uint8Array, n: number): string {
  return `${bytesToBase64(dhPub32)}:${n}`;
}

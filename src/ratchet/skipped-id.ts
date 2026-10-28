/**
 * Skipped message keys are stored under `${base64(32-byte DH public key)}:${message number}`.
 * The ratchet builds these ids; the deserializers accept only ids in this grammar, since
 * anything else can never match an incoming message and only takes up space.
 */

import { bytesToBase64 } from "../encoding/base64.js";

export const SKIPPED_KEY_ID = /^[A-Za-z0-9+/]{43}=:(0|[1-9][0-9]{0,15})$/;

export function skippedKeyId(dhPub32: Uint8Array, n: number): string {
  return `${bytesToBase64(dhPub32)}:${n}`;
}

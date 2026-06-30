/**
 * Direction-scoped session id derivation.
 *
 * A conversation between two devices uses two distinct ratchet sessions — one
 * per direction — so the storage id must incorporate both device ids AND the
 * direction. The id is a SHA-256 of `my||their||direction`, base64url-encoded
 * and length-bounded, with a `dr_` prefix. It is a stable, collision-resistant
 * key, not a secret.
 */

import { sha256 } from "@noble/hashes/sha2.js";
import { utf8ToBytes } from "@noble/hashes/utils.js";
import { bytesToBase64 } from "./encoding/base64.js";

export type SessionDirectionV1 = "send" | "recv";

const MIN_LEN = 16;
const MAX_LEN = 80;
const DEFAULT_LEN = 52;

/** Standard base64 → URL-safe, unpadded. */
function toBase64Url(bytes: Uint8Array): string {
  return bytesToBase64(bytes)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

/**
 * Derives a stable, direction-scoped session id for a device pair.
 *
 * @param args.my_device_id - This device's id
 * @param args.their_device_id - The peer device's id
 * @param args.direction - 'send' or 'recv' (the two sessions are independent)
 * @param args.max_len - Optional length cap for the encoded portion (clamped to [16, 80], default 52)
 * @returns A `dr_`-prefixed identifier
 */
export function deriveDirectionScopedSessionIdV1(args: {
  my_device_id: string;
  their_device_id: string;
  direction: SessionDirectionV1;
  max_len?: number;
}): string {
  const material = `${args.my_device_id}||${args.their_device_id}||${args.direction}`;
  const digest = sha256(utf8ToBytes(material));
  const encoded = toBase64Url(digest);
  const bounded = encoded.slice(
    0,
    Math.min(Math.max(args.max_len ?? DEFAULT_LEN, MIN_LEN), MAX_LEN)
  );
  return `dr_${bounded}`;
}

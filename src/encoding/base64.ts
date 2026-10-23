/**
 * Base64 encoding/decoding utilities for browser and Node.js environments.
 */

// Strict RFC4648 base64 (not base64url) validation regex
const STRICT_B64_RE =
  /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

const B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 * RFC 4648 §3.5: the bits a padded final group does not use must be zero. Without
 * this, several strings decode to the same bytes (for example "AB==" and "AA==").
 */
function hasZeroPadBits(b64: string): boolean {
  if (b64.endsWith("==")) return (B64_ALPHABET.indexOf(b64[b64.length - 3]!) & 0x0f) === 0;
  if (b64.endsWith("=")) return (B64_ALPHABET.indexOf(b64[b64.length - 2]!) & 0x03) === 0;
  return true;
}

/**
 * Convert a Uint8Array to a base64 string.
 * Uses Node.js Buffer when available, otherwise falls back to browser implementation.
 */
export function bytesToBase64(bytes: Uint8Array): string {
  // Node.js environment
  if (typeof Buffer !== "undefined") {
    return Buffer.from(bytes).toString("base64");
  }

  // Browser environment
  let binary = "";
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]!);
  }
  return btoa(binary);
}

/**
 * Convert a base64 string to a Uint8Array.
 * Uses Node.js Buffer when available, otherwise falls back to browser implementation.
 */
export function base64ToBytes(b64: string): Uint8Array {
  // Node.js environment
  if (typeof Buffer !== "undefined") {
    return new Uint8Array(Buffer.from(b64, "base64"));
  }

  // Browser environment
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Validates strict, canonical RFC4648 base64 (no url-safe alphabet, no whitespace,
 * zero padding bits), so each byte string has exactly one accepted encoding.
 * Throws TypeError on invalid input.
 */
export function assertStrictBase64(label: string, b64: string): void {
  if (typeof b64 !== "string" || b64.length === 0) {
    throw new TypeError(`Invalid ${label}: not valid base64`);
  }
  if (b64.length % 4 !== 0) {
    throw new TypeError(`Invalid ${label}: not valid base64`);
  }
  if (!STRICT_B64_RE.test(b64) || !hasZeroPadBits(b64)) {
    throw new TypeError(`Invalid ${label}: not valid base64`);
  }
}

/**
 * Strict base64 decoder that enforces RFC4648 formatting before decoding.
 */
export function decodeStrictBase64(label: string, b64: string): Uint8Array {
  assertStrictBase64(label, b64);
  return base64ToBytes(b64);
}

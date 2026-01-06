/**
 * Base64 encoding/decoding utilities for browser and Node.js environments.
 */

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

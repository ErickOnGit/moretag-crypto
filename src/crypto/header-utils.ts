import { base64ToBytes } from "../encoding/base64.js";

function assertStrictBase64(label: string, b64: string): void {
  // Strict RFC4648 base64 (not base64url), no whitespace.
  // Must be length % 4 == 0 with proper padding.
  if (typeof b64 !== "string" || b64.length === 0) {
    throw new TypeError(`Invalid ${label}: not valid base64`);
  }
  if (b64.length % 4 !== 0) {
    throw new TypeError(`Invalid ${label}: not valid base64`);
  }
  const re =
    /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
  if (!re.test(b64)) {
    throw new TypeError(`Invalid ${label}: not valid base64`);
  }
}

/**
 * Decodes nonce_b64 and enforces 24-byte length.
 */
export function decodeNonceFromHeaderV1(header: { nonce_b64: string }): Uint8Array {
  assertStrictBase64("nonce_b64", header.nonce_b64);

  const nonce = base64ToBytes(header.nonce_b64);
  if (nonce.byteLength !== 24) {
    throw new TypeError(
      `Invalid nonce length from header: expected 24 bytes, got ${nonce.byteLength}`
    );
  }
  return nonce;
}

/**
 * Decodes dr.dh_pub_b64 and enforces 32-byte length.
 */
export function decodeDhPubFromHeaderV1(header: {
  dr: { dh_pub_b64: string };
}): Uint8Array {
  assertStrictBase64("dr.dh_pub_b64", header.dr.dh_pub_b64);

  const dhPub = base64ToBytes(header.dr.dh_pub_b64);
  if (dhPub.byteLength !== 32) {
    throw new TypeError(
      `Invalid dr.dh_pub_b64 length: expected 32 bytes, got ${dhPub.byteLength}`
    );
  }
  return dhPub;
}

/**
 * Strict decode helper you can reuse for ciphertext, if you want it centralized.
 */
export function decodeStrictBase64(label: string, b64: string): Uint8Array {
  assertStrictBase64(label, b64);
  return base64ToBytes(b64);
}

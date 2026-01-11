import { decodeStrictBase64 as decodeStrictBase64Internal } from "../encoding/base64.js";

/**
 * Decodes nonce_b64 and enforces 24-byte length.
 */
export function decodeNonceFromHeaderV1(header: { nonce_b64: string }): Uint8Array {
  const nonce = decodeStrictBase64Internal("nonce_b64", header.nonce_b64);
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
  const dhPub = decodeStrictBase64Internal("dr.dh_pub_b64", header.dr.dh_pub_b64);
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
  return decodeStrictBase64Internal(label, b64);
}

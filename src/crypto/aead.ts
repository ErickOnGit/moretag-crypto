import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { randomBytes } from "@noble/ciphers/utils.js";

const KEY_LENGTH = 32;
const NONCE_LENGTH = 24;

/**
 * Generates a cryptographically secure random 24-byte nonce.
 */
export function randomNonce24(): Uint8Array {
  return randomBytes(NONCE_LENGTH);
}

/**
 * Validates that the key and nonce have the correct lengths for XChaCha20-Poly1305.
 * Throws TypeError if lengths are incorrect.
 */
export function assertKeyNonceLengths(
  key32: Uint8Array,
  nonce24: Uint8Array
): void {
  if (key32.byteLength !== KEY_LENGTH) {
    throw new TypeError(
      `Invalid key length: expected ${KEY_LENGTH} bytes, got ${key32.byteLength}`
    );
  }
  if (nonce24.byteLength !== NONCE_LENGTH) {
    throw new TypeError(
      `Invalid nonce length: expected ${NONCE_LENGTH} bytes, got ${nonce24.byteLength}`
    );
  }
}

/**
 * Encrypts plaintext using XChaCha20-Poly1305 with AAD.
 *
 * @param key32 - 32-byte secret key
 * @param nonce24 - 24-byte unique nonce
 * @param plaintext - Data to encrypt
 * @param aad - Additional Authenticated Data (integrity protected but not encrypted)
 * @returns Ciphertext (includes authentication tag)
 */
export function aeadEncryptXChaCha20Poly1305(
  key32: Uint8Array,
  nonce24: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array
): Uint8Array {
  assertKeyNonceLengths(key32, nonce24);
  const cipher = xchacha20poly1305(key32, nonce24, aad);
  return cipher.encrypt(plaintext);
}

/**
 * Decrypts ciphertext using XChaCha20-Poly1305 with AAD.
 * Throws an error if authentication fails (wrong key, modified ciphertext, or modified AAD).
 *
 * @param key32 - 32-byte secret key
 * @param nonce24 - 24-byte unique nonce
 * @param ciphertext - Encrypted data (includes authentication tag)
 * @param aad - Additional Authenticated Data
 * @returns Decrypted plaintext
 */
export function aeadDecryptXChaCha20Poly1305(
  key32: Uint8Array,
  nonce24: Uint8Array,
  ciphertext: Uint8Array,
  aad: Uint8Array
): Uint8Array {
  assertKeyNonceLengths(key32, nonce24);
  const cipher = xchacha20poly1305(key32, nonce24, aad);
  // Encrypted data authentication tag is verified internally by @noble/ciphers
  return cipher.decrypt(ciphertext);
}

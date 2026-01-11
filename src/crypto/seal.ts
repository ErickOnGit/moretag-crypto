/**
 * High-level seal/open primitives for v1 E2EE protocol.
 * Combines AAD encoding, AEAD encryption, and base64 encoding.
 */

import type { HeaderProtoV1, ArchiveHeaderV1 } from "../wire/header.js";
import { encodeAADFromHeaderV1 } from "./aad.js";
import {
  aeadEncryptXChaCha20Poly1305,
  aeadDecryptXChaCha20Poly1305,
} from "./aead.js";
import {
  decodeNonceFromHeaderV1,
  decodeDhPubFromHeaderV1,
} from "./header-utils.js";
import { bytesToBase64, decodeStrictBase64 } from "../encoding/base64.js";
import { MAX_PLAINTEXT_BYTES, MAX_CIPHERTEXT_BYTES } from "./limits.js";

/**
 * Seals (encrypts) a delivery message using HeaderProtoV1.
 *
 * @param args.key32 - 32-byte encryption key
 * @param args.header - Protocol header (used as AAD)
 * @param args.plaintext - Data to encrypt
 * @returns Object containing base64-encoded ciphertext
 * @throws TypeError if header fields are invalid (nonce, dh_pub lengths or base64)
 */
export function sealDeliveryV1(args: {
  key32: Uint8Array;
  header: HeaderProtoV1;
  plaintext: Uint8Array;
}): { ciphertext_b64: string } {
  const { key32, header, plaintext } = args;

  if (plaintext.byteLength > MAX_PLAINTEXT_BYTES) {
    throw new TypeError(
      `Plaintext too large: max ${MAX_PLAINTEXT_BYTES} bytes`
    );
  }

  // Compute AAD from header
  const aadBytes = encodeAADFromHeaderV1(header);

  // Decode and validate nonce (24 bytes)
  const nonce24 = decodeNonceFromHeaderV1(header);

  // Decode and validate DH public key (32 bytes) - enforces crypto invariant
  // even though we don't use it yet
  decodeDhPubFromHeaderV1(header);

  // Encrypt
  const ciphertextBytes = aeadEncryptXChaCha20Poly1305(
    key32,
    nonce24,
    plaintext,
    aadBytes
  );

  return { ciphertext_b64: bytesToBase64(ciphertextBytes) };
}

/**
 * Opens (decrypts) a delivery message using HeaderProtoV1.
 *
 * @param args.key32 - 32-byte encryption key
 * @param args.header - Protocol header (used as AAD)
 * @param args.ciphertext_b64 - Base64-encoded ciphertext
 * @returns Decrypted plaintext
 * @throws TypeError if header fields or ciphertext_b64 are invalid
 * @throws Error if authentication fails (wrong key, tampered data)
 */
export function openDeliveryV1(args: {
  key32: Uint8Array;
  header: HeaderProtoV1;
  ciphertext_b64: string;
}): Uint8Array {
  const { key32, header, ciphertext_b64 } = args;

  // Compute AAD from header
  const aadBytes = encodeAADFromHeaderV1(header);

  // Decode and validate nonce (24 bytes)
  const nonce24 = decodeNonceFromHeaderV1(header);

  // Decode and validate DH public key (32 bytes)
  decodeDhPubFromHeaderV1(header);

  // Decode ciphertext from base64
  const ciphertextBytes = decodeStrictBase64("ciphertext_b64", ciphertext_b64);
  if (ciphertextBytes.byteLength > MAX_CIPHERTEXT_BYTES) {
    throw new TypeError(
      `Ciphertext too large: max ${MAX_CIPHERTEXT_BYTES} bytes`
    );
  }

  // Decrypt
  return aeadDecryptXChaCha20Poly1305(
    key32,
    nonce24,
    ciphertextBytes,
    aadBytes
  );
}

/**
 * Seals (encrypts) an archive event using ArchiveHeaderV1.
 *
 * @param args.key32 - 32-byte encryption key
 * @param args.header - Archive header (used as AAD)
 * @param args.plaintext - Data to encrypt
 * @returns Object containing base64-encoded ciphertext
 * @throws TypeError if header fields are invalid (nonce, dh_pub lengths or base64)
 */
export function sealArchiveV1(args: {
  key32: Uint8Array;
  header: ArchiveHeaderV1;
  plaintext: Uint8Array;
}): { ciphertext_b64: string } {
  const { key32, header, plaintext } = args;

  if (plaintext.byteLength > MAX_PLAINTEXT_BYTES) {
    throw new TypeError(
      `Plaintext too large: max ${MAX_PLAINTEXT_BYTES} bytes`
    );
  }

  // Compute AAD from header
  const aadBytes = encodeAADFromHeaderV1(header);

  // Decode and validate nonce (24 bytes)
  const nonce24 = decodeNonceFromHeaderV1(header);

  // Decode and validate DH public key (32 bytes)
  decodeDhPubFromHeaderV1(header);

  // Encrypt
  const ciphertextBytes = aeadEncryptXChaCha20Poly1305(
    key32,
    nonce24,
    plaintext,
    aadBytes
  );

  return { ciphertext_b64: bytesToBase64(ciphertextBytes) };
}

/**
 * Opens (decrypts) an archive event using ArchiveHeaderV1.
 *
 * @param args.key32 - 32-byte encryption key
 * @param args.header - Archive header (used as AAD)
 * @param args.ciphertext_b64 - Base64-encoded ciphertext
 * @returns Decrypted plaintext
 * @throws TypeError if header fields or ciphertext_b64 are invalid
 * @throws Error if authentication fails (wrong key, tampered data)
 */
export function openArchiveV1(args: {
  key32: Uint8Array;
  header: ArchiveHeaderV1;
  ciphertext_b64: string;
}): Uint8Array {
  const { key32, header, ciphertext_b64 } = args;

  // Compute AAD from header
  const aadBytes = encodeAADFromHeaderV1(header);

  // Decode and validate nonce (24 bytes)
  const nonce24 = decodeNonceFromHeaderV1(header);

  // Decode and validate DH public key (32 bytes)
  decodeDhPubFromHeaderV1(header);

  // Decode ciphertext from base64
  const ciphertextBytes = decodeStrictBase64("ciphertext_b64", ciphertext_b64);
  if (ciphertextBytes.byteLength > MAX_CIPHERTEXT_BYTES) {
    throw new TypeError(
      `Ciphertext too large: max ${MAX_CIPHERTEXT_BYTES} bytes`
    );
  }

  // Decrypt
  return aeadDecryptXChaCha20Poly1305(
    key32,
    nonce24,
    ciphertextBytes,
    aadBytes
  );
}

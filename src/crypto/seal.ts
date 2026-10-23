/**
 * High-level seal/open primitives (protocol v2): message delivery under AD || H,
 * local seals under a caller key and AAD, and attachments.
 */

import type { HeaderProtoV2 } from "../wire/header.js";
import { decodeCiphertextV2, decodeHeaderV2 } from "../wire/header.js";
import { buildDeliveryAadFromDecodedV2 } from "./aad.js";
import {
  aeadEncryptXChaCha20Poly1305,
  aeadDecryptXChaCha20Poly1305,
  randomKey32,
  randomNonce24,
} from "./aead.js";
import { assertCanonicalDeviceId } from "./device-id.js";
import { encodeCbor } from "../encoding/cbor.js";
import { bytesToBase64, decodeStrictBase64 } from "../encoding/base64.js";
import { MAX_PLAINTEXT_BYTES, MAX_CIPHERTEXT_BYTES } from "./limits.js";

/** Attachments carry no header, so they are sealed with empty AAD. */
const EMPTY_AAD = new Uint8Array(0);

function assertPlaintextSize(plaintext: Uint8Array): void {
  if (plaintext.byteLength > MAX_PLAINTEXT_BYTES) {
    throw new TypeError(`Plaintext too large: max ${MAX_PLAINTEXT_BYTES} bytes`);
  }
}

/** A local seal's ciphertext, which the host holds: a TypeError when malformed. */
function decodeLocalCiphertext(ciphertext_b64: string): Uint8Array {
  const bytes = decodeStrictBase64("ciphertext_b64", ciphertext_b64);
  if (bytes.byteLength > MAX_CIPHERTEXT_BYTES) {
    throw new TypeError(`Ciphertext too large: max ${MAX_CIPHERTEXT_BYTES} bytes`);
  }
  return bytes;
}

/**
 * Seals one message under its message key with AAD = AD || H.
 *
 * @param args.key32 - 32-byte message key
 * @param args.ad - the session's 164-byte associated data
 * @param args.header - the v2 header; its nonce is the AEAD nonce and H its AAD half
 * @throws InvalidWireError / InvalidDeviceIdError for a malformed header, TypeError for a bad AD
 */
export function sealDeliveryV2(args: {
  key32: Uint8Array;
  ad: Uint8Array;
  header: HeaderProtoV2;
  plaintext: Uint8Array;
}): { ciphertext_b64: string } {
  assertPlaintextSize(args.plaintext);
  const h = decodeHeaderV2(args.header);
  const aad = buildDeliveryAadFromDecodedV2(args.ad, h);
  const ciphertext = aeadEncryptXChaCha20Poly1305(args.key32, h.nonce24, args.plaintext, aad);
  return { ciphertext_b64: bytesToBase64(ciphertext) };
}

/**
 * Opens one message sealed by {@link sealDeliveryV2}.
 *
 * @throws InvalidWireError `invalid_header` for a malformed header, or a
 *   `ciphertext_b64` that is not strict base64 or is over MAX_CIPHERTEXT_BYTES
 * @throws DecryptFailedError if authentication fails (wrong key, AD, header or ciphertext)
 */
export function openDeliveryV2(args: {
  key32: Uint8Array;
  ad: Uint8Array;
  header: HeaderProtoV2;
  ciphertext_b64: string;
}): Uint8Array {
  const h = decodeHeaderV2(args.header);
  const aad = buildDeliveryAadFromDecodedV2(args.ad, h);
  const ciphertext = decodeCiphertextV2(args.ciphertext_b64);
  return aeadDecryptXChaCha20Poly1305(args.key32, h.nonce24, ciphertext, aad);
}

/**
 * The AAD of a self seal: CBOR ["moretag/self/v1", device_id], the device id as a
 * canonical UUID text string. A host that keeps its own copy of what it sent
 * seals it with {@link sealLocalV2} under a device-local key and this AAD.
 */
export function buildSelfSealAadV2(device_id: string): Uint8Array {
  assertCanonicalDeviceId(device_id);
  return encodeCbor(["moretag/self/v1", device_id]);
}

/**
 * Seals data for this device only: XChaCha20-Poly1305 under a caller key, a fresh
 * random 24-byte nonce (one draw) and caller AAD. No ratchet is involved.
 */
export function sealLocalV2(args: {
  key32: Uint8Array;
  aad: Uint8Array;
  plaintext: Uint8Array;
}): { nonce_b64: string; ciphertext_b64: string } {
  assertPlaintextSize(args.plaintext);
  const nonce24 = randomNonce24();
  const ciphertext = aeadEncryptXChaCha20Poly1305(args.key32, nonce24, args.plaintext, args.aad);
  return { nonce_b64: bytesToBase64(nonce24), ciphertext_b64: bytesToBase64(ciphertext) };
}

/**
 * Opens a {@link sealLocalV2} seal.
 *
 * @throws DecryptFailedError if authentication fails
 */
export function openLocalV2(args: {
  key32: Uint8Array;
  aad: Uint8Array;
  nonce_b64: string;
  ciphertext_b64: string;
}): Uint8Array {
  const nonce24 = decodeStrictBase64("nonce_b64", args.nonce_b64);
  const ciphertext = decodeLocalCiphertext(args.ciphertext_b64);
  return aeadDecryptXChaCha20Poly1305(args.key32, nonce24, ciphertext, args.aad);
}

/**
 * Seals (encrypts) an attachment blob with a standalone, single-use symmetric key.
 *
 * Unlike sealDeliveryV2, attachments are not bound to a ratchet header: the
 * returned key/nonce travel inside the (already E2EE) ratcheted message that
 * references the uploaded ciphertext, so no AAD is needed — the AEAD tag alone
 * authenticates the bytes. A fresh random key per attachment makes nonce reuse a
 * non-issue. The binary ciphertext is intended to be uploaded as-is to storage.
 *
 * @param args.plaintext - Attachment bytes to encrypt
 * @param args.key32 - Optional 32-byte key (defaults to a fresh random key)
 * @param args.nonce24 - Optional 24-byte nonce (defaults to a fresh random nonce)
 * @returns base64 key/nonce (to embed in the ratcheted message) and binary ciphertext
 */
export function sealAttachmentV1(args: {
  plaintext: Uint8Array;
  key32?: Uint8Array;
  nonce24?: Uint8Array;
}): { key_b64: string; nonce_b64: string; ciphertext: Uint8Array } {
  const key32 = args.key32 ?? randomKey32();
  const nonce24 = args.nonce24 ?? randomNonce24();

  const ciphertext = aeadEncryptXChaCha20Poly1305(
    key32,
    nonce24,
    args.plaintext,
    EMPTY_AAD
  );

  return {
    key_b64: bytesToBase64(key32),
    nonce_b64: bytesToBase64(nonce24),
    ciphertext,
  };
}

/**
 * Opens (decrypts) an attachment blob sealed with sealAttachmentV1.
 *
 * @param args.key_b64 - Base64-encoded 32-byte key (from the ratcheted message)
 * @param args.nonce_b64 - Base64-encoded 24-byte nonce
 * @param args.ciphertext - Binary ciphertext downloaded from storage
 * @returns Decrypted attachment bytes
 * @throws TypeError if key/nonce are not valid base64 or wrong length
 * @throws DecryptFailedError if authentication fails (wrong key, tampered ciphertext)
 */
export function openAttachmentV1(args: {
  key_b64: string;
  nonce_b64: string;
  ciphertext: Uint8Array;
}): Uint8Array {
  const key32 = decodeStrictBase64("key_b64", args.key_b64);
  const nonce24 = decodeStrictBase64("nonce_b64", args.nonce_b64);

  return aeadDecryptXChaCha20Poly1305(
    key32,
    nonce24,
    args.ciphertext,
    EMPTY_AAD
  );
}

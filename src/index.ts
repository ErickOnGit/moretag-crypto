/**
 * Public API for moretag-crypto v1.
 * Exports wire format types, encoding utilities, and validators.
 */

// Core types
export type { UUID, Base64String } from "./types.js";

// Wire format types
export type {
  HeaderProtoV1,
  ArchiveHeaderV1,
  DoubleRatchetHeader,
} from "./wire/header.js";

export type { MessagePayloadV1 } from "./wire/payload.js";

export type {
  X3DHPrekeyBundleV1,
  X3DHSessionInitV1,
} from "./wire/x3dh.js";

// Validators
export {
  assertHeaderProtoV1,
  assertArchiveHeaderV1,
} from "./wire/header.js";

export {
  assertX3DHPrekeyBundleV1,
  assertX3DHSessionInitV1,
} from "./wire/x3dh.js";

// Encoding utilities
export { bytesToBase64, base64ToBytes } from "./encoding/base64.js";

// Crypto fundamentals
export { encodeAADFromHeaderV1 } from "./crypto/aad.js";
export {
  randomNonce24,
  assertKeyNonceLengths,
  aeadEncryptXChaCha20Poly1305,
  aeadDecryptXChaCha20Poly1305,
} from "./crypto/aead.js";
export {
  decodeNonceFromHeaderV1,
  decodeDhPubFromHeaderV1,
} from "./crypto/header-utils.js";

// High-level seal/open primitives
export {
  sealDeliveryV1,
  openDeliveryV1,
  sealArchiveV1,
  openArchiveV1,
} from "./crypto/seal.js";

// X25519 key agreement
export { generateX25519Keypair, x25519SharedSecret } from "./crypto/x25519.js";

// Key derivation
export { hkdfSha256 } from "./crypto/hkdf.js";
export { kdfRootAndChainKey, kdfChainKey } from "./crypto/kdf.js";

// Ed25519 signing
export { generateEd25519Keypair, ed25519Sign, ed25519Verify } from "./crypto/ed25519.js";

// X3DH crypto
export { decodeX25519PubB64, x3dhInitiatorV1, x3dhResponderV1 } from "./crypto/x3dh.js";


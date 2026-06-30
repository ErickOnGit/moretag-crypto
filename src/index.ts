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
  randomKey32,
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
  sealAttachmentV1,
  openAttachmentV1,
} from "./crypto/seal.js";

// Typed errors (consumers branch on these via instanceof)
export {
  ReplayDetectedError,
  SessionNotFoundError,
  RatchetStoreConflictError,
  IdentityMismatchError,
} from "./errors.js";

// Direction-scoped session id derivation
export { deriveDirectionScopedSessionIdV1 } from "./session-id.js";
export type { SessionDirectionV1 } from "./session-id.js";

// X25519 key agreement
export {
  generateX25519Keypair,
  x25519SharedSecret,
  x25519PublicFromPrivate,
} from "./crypto/x25519.js";

// Key derivation
export { hkdfSha256 } from "./crypto/hkdf.js";
export { kdfRootAndChainKey, kdfChainKey } from "./crypto/kdf.js";

// Ed25519 signing
export { generateEd25519Keypair, ed25519Sign, ed25519Verify } from "./crypto/ed25519.js";

// X3DH crypto
export { x3dhInitiatorV1, x3dhResponderV1 } from "./crypto/x3dh.js";

// Double Ratchet
export {
  ratchetInit,
  ratchetEncrypt,
  ratchetDecrypt,
  type RatchetState,
} from "./ratchet/ratchet.js";
export {
  InMemoryRatchetStore,
  ratchetEncryptWithStore,
  ratchetDecryptWithStore,
  type RatchetSessionStore,
  type PersistedSession,
  createPersistedSession,
} from "./ratchet/session-store.js";
export {
  serializeRatchetStateV1,
  deserializeRatchetStateV1,
  serializePersistedSessionV1,
  deserializePersistedSessionV1,
  type SerializedRatchetStateV1,
  type SerializedPersistedSessionV1,
} from "./ratchet/serialization.js";
export { FileRatchetStore } from "./ratchet/file-store.js";

// Identity trust helpers
export {
  IdentityRegistry,
  type IdentityRecordV1,
  type IdentityRegistryStateV1,
} from "./identity/trust.js";

// X3DH prekey lifecycle helpers
export {
  X3DHPrekeyManagerV1,
  type SignedPrekeyRecord,
  type OneTimePrekeyRecord,
  type SerializedSignedPrekeyV1,
  type SerializedOneTimePrekeyV1,
  type X3DHPrekeyManagerStateV1,
} from "./x3dh/prekey-manager.js";
export {
  x3dhInitiatorWithTrustV1,
  x3dhResponderWithPrekeysV1,
  x3dhInitiatorBootstrapV1,
  x3dhResponderBootstrapV1,
} from "./x3dh/session.js";

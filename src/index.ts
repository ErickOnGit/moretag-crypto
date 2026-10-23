/**
 * Public API for moretag-crypto 3.x: protocol v2 of our X3DH and Double Ratchet.
 * See docs/SPEC.md for the exact formats.
 */

// Core types
export type { UUID, Base64String } from "./types.js";

// Wire formats and their validators
export type {
  HeaderProtoV2,
  DoubleRatchetHeader,
  GroupSlotV2,
  DecodedHeaderV2,
} from "./wire/header.js";
export { assertHeaderProtoV2, decodeHeaderV2 } from "./wire/header.js";

export type { MessagePayloadV1 } from "./wire/payload.js";

export type {
  X3DHPrekeyBundleV2,
  X3DHSessionInitV2,
  DecodedPrekeyBundleV2,
  DecodedSessionInitV2,
} from "./wire/x3dh.js";
export {
  X3DH_ALG_V2,
  MAX_PREKEY_ID,
  assertX3DHPrekeyBundleV2,
  assertX3DHSessionInitV2,
  decodePrekeyBundleV2,
  decodeSessionInitV2,
} from "./wire/x3dh.js";

// Encoding utilities
export { bytesToBase64, base64ToBytes } from "./encoding/base64.js";

// Pluggable low-level primitives (pure-JS @noble by default; hosts may inject
// faster native implementations — see crypto/primitives.ts for the contract)
export {
  registerCryptoPrimitives,
  resetCryptoPrimitives,
  getCryptoPrimitivesProviderName,
  type CryptoPrimitives,
  type CryptoPrimitivesProvider,
} from "./crypto/primitives.js";
// Adapter for Node-crypto-shaped backends lives at
// "moretag-crypto/providers/node-crypto" (kept out of this entry so the
// default import graph stays exactly as before).

// Device ids and the session's associated data
export {
  isCanonicalDeviceId,
  assertCanonicalDeviceId,
  deviceIdToBytes,
  deviceIdFromBytes,
} from "./crypto/device-id.js";
export {
  ASSOCIATED_DATA_V2_LENGTH,
  buildAssociatedDataV2,
  parseAssociatedDataV2,
  type AssociatedDataV2,
} from "./crypto/ad.js";

// Crypto fundamentals
export { buildDeliveryAadV2, encodeHeaderV2 } from "./crypto/aad.js";
export {
  randomNonce24,
  randomKey32,
  assertKeyNonceLengths,
  aeadEncryptXChaCha20Poly1305,
  aeadDecryptXChaCha20Poly1305,
} from "./crypto/aead.js";

// High-level seal/open primitives
export {
  sealDeliveryV2,
  openDeliveryV2,
  buildSelfSealAadV2,
  sealLocalV2,
  openLocalV2,
  sealAttachmentV1,
  openAttachmentV1,
} from "./crypto/seal.js";

// Typed errors (consumers branch on these via instanceof or `code`)
export {
  ReplayDetectedError,
  SessionNotFoundError,
  RatchetStoreConflictError,
  IdentityMismatchError,
  DecryptFailedError,
  UnknownPrekeyError,
  DeviceMismatchError,
  SelfSessionError,
  NoSendingChainError,
  InvalidDeviceIdError,
  InvalidWireError,
  BadSignatureError,
  LowOrderKeyError,
  type InvalidWireCode,
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

// X3DH
export {
  SPK_SIGNATURE_DOMAIN,
  OPK_BATCH_SIGNATURE_DOMAIN,
  buildSpkSigMessage,
  buildOpkBatchSigMessage,
  verifyPrekeyBundleV2,
  x3dhInitiatorV2,
  x3dhResponderV2,
} from "./crypto/x3dh.js";

// Double Ratchet
export {
  ratchetInitInitiatorV2,
  ratchetInitResponderV2,
  ratchetEncrypt,
  ratchetDecrypt,
  cloneRatchetState,
  type RatchetState,
  type RatchetRole,
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
  serializeRatchetStateV2,
  deserializeRatchetStateV2,
  serializePersistedSessionV2,
  deserializePersistedSessionV2,
  type SerializedRatchetStateV2,
  type SerializedPersistedSessionV2,
} from "./ratchet/serialization.js";
// FileRatchetStore is Node-only (fs); import from "moretag-crypto/node" — keeps this entry fs-free.

// Identity trust helpers
export {
  IdentityRegistry,
  type IdentityRecordV1,
  type IdentityRegistryStateV1,
} from "./identity/trust.js";

// X3DH prekey lifecycle helpers
export {
  X3DHPrekeyManagerV2,
  type SignedPrekeyRecord,
  type OneTimePrekeyRecord,
  type SerializedSignedPrekeyV2,
  type SerializedOneTimePrekeyV2,
  type X3DHPrekeyManagerStateV2,
} from "./x3dh/prekey-manager.js";
export { x3dhInitiatorBootstrapV2, x3dhResponderBootstrapV2 } from "./x3dh/session.js";

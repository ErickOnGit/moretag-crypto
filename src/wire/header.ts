/**
 * Wire format header types for v1 protocol.
 * These structures are part of the frozen v1 contract and will be used as AAD (Additional Authenticated Data).
 */

/**
 * Double Ratchet header placeholder for v1.
 * Contains the Diffie-Hellman public key and chain counters.
 */
export interface DoubleRatchetHeader {
  /** Base64-encoded Curve25519 public key (32 bytes) */
  dh_pub_b64: string;
  /** Previous chain length */
  pn: number;
  /** Message number in current chain */
  n: number;
}

/**
 * Protocol header for peer-to-peer messages (v1).
 * Used as AAD for XChaCha20-Poly1305 encryption.
 * JSON-serializable for wire transport.
 */
export interface HeaderProtoV1 {
  /** Protocol version */
  v: 1;
  /** Encryption algorithm identifier */
  alg: "xchacha20poly1305";
  /** Base64-encoded 24-byte nonce for XChaCha20-Poly1305 */
  nonce_b64: string;
  /** UUID of the sending device */
  sender_device_id: string;
  /** UUID of the recipient device (for per-device deliveries) */
  recipient_device_id: string;
  /** Double Ratchet header placeholder */
  dr: DoubleRatchetHeader;
}

/**
 * Archive header for logical archive events (v1).
 * Similar to HeaderProtoV1 but without recipient_device_id (archive is sender-local).
 */
export interface ArchiveHeaderV1 {
  /** Protocol version */
  v: 1;
  /** Encryption algorithm identifier */
  alg: "xchacha20poly1305";
  /** Base64-encoded 24-byte nonce for XChaCha20-Poly1305 */
  nonce_b64: string;
  /** UUID of the device creating the archive */
  sender_device_id: string;
  /** Double Ratchet header placeholder */
  dr: DoubleRatchetHeader;
}

/**
 * Runtime validator for HeaderProtoV1.
 * Throws TypeError if validation fails.
 */
export function assertHeaderProtoV1(x: unknown): asserts x is HeaderProtoV1 {
  if (!x || typeof x !== "object") {
    throw new TypeError("HeaderProtoV1 must be an object");
  }

  const obj = x as Record<string, unknown>;

  if (obj.v !== 1) {
    throw new TypeError("HeaderProtoV1.v must be 1");
  }

  if (obj.alg !== "xchacha20poly1305") {
    throw new TypeError('HeaderProtoV1.alg must be "xchacha20poly1305"');
  }

  if (typeof obj.nonce_b64 !== "string" || obj.nonce_b64.length === 0) {
    throw new TypeError("HeaderProtoV1.nonce_b64 must be a non-empty string");
  }

  if (
    typeof obj.sender_device_id !== "string" ||
    obj.sender_device_id.length === 0
  ) {
    throw new TypeError(
      "HeaderProtoV1.sender_device_id must be a non-empty string"
    );
  }

  if (
    typeof obj.recipient_device_id !== "string" ||
    obj.recipient_device_id.length === 0
  ) {
    throw new TypeError(
      "HeaderProtoV1.recipient_device_id must be a non-empty string"
    );
  }

  if (!obj.dr || typeof obj.dr !== "object") {
    throw new TypeError("HeaderProtoV1.dr must be an object");
  }

  const dr = obj.dr as Record<string, unknown>;

  if (typeof dr.dh_pub_b64 !== "string" || dr.dh_pub_b64.length === 0) {
    throw new TypeError("HeaderProtoV1.dr.dh_pub_b64 must be a non-empty string");
  }

  if (typeof dr.pn !== "number" || !Number.isFinite(dr.pn)) {
    throw new TypeError("HeaderProtoV1.dr.pn must be a finite number");
  }

  if (typeof dr.n !== "number" || !Number.isFinite(dr.n)) {
    throw new TypeError("HeaderProtoV1.dr.n must be a finite number");
  }
}

/**
 * Runtime validator for ArchiveHeaderV1.
 * Throws TypeError if validation fails.
 */
export function assertArchiveHeaderV1(
  x: unknown
): asserts x is ArchiveHeaderV1 {
  if (!x || typeof x !== "object") {
    throw new TypeError("ArchiveHeaderV1 must be an object");
  }

  const obj = x as Record<string, unknown>;

  if (obj.v !== 1) {
    throw new TypeError("ArchiveHeaderV1.v must be 1");
  }

  if (obj.alg !== "xchacha20poly1305") {
    throw new TypeError('ArchiveHeaderV1.alg must be "xchacha20poly1305"');
  }

  if (typeof obj.nonce_b64 !== "string" || obj.nonce_b64.length === 0) {
    throw new TypeError("ArchiveHeaderV1.nonce_b64 must be a non-empty string");
  }

  if (
    typeof obj.sender_device_id !== "string" ||
    obj.sender_device_id.length === 0
  ) {
    throw new TypeError(
      "ArchiveHeaderV1.sender_device_id must be a non-empty string"
    );
  }

  if (!obj.dr || typeof obj.dr !== "object") {
    throw new TypeError("ArchiveHeaderV1.dr must be an object");
  }

  const dr = obj.dr as Record<string, unknown>;

  if (typeof dr.dh_pub_b64 !== "string" || dr.dh_pub_b64.length === 0) {
    throw new TypeError(
      "ArchiveHeaderV1.dr.dh_pub_b64 must be a non-empty string"
    );
  }

  if (typeof dr.pn !== "number" || !Number.isFinite(dr.pn)) {
    throw new TypeError("ArchiveHeaderV1.dr.pn must be a finite number");
  }

  if (typeof dr.n !== "number" || !Number.isFinite(dr.n)) {
    throw new TypeError("ArchiveHeaderV1.dr.n must be a finite number");
  }
}

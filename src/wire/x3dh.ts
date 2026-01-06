/**
 * Structural validators for X3DH wire format types (v1).
 * Validates object shape but does NOT enforce base64 validity or decoded lengths.
 *
 * Crypto-layer checks (base64 decode + length, signature verify) live in src/crypto/x3dh.ts.
 */

export type X3DHPrekeyId = number | string;

/**
 * X3DH prekey bundle (wire format) v1.
 * - X25519 identity key for DH: ik_pub_b64
 * - X25519 signed prekey for DH: spk_pub_b64
 * - Ed25519 public key for signature verification: ik_sig_pub_b64
 * - Ed25519 signature over SPK (and binding fields): spk_sig_b64
 * - Optional OPK (one-time prekey) + opk_id if present
 * - spk_id REQUIRED so the responder can look up the private SPK later
 */
export interface X3DHPrekeyBundleV1 {
  v: 1;
  alg: "x3dh-x25519-hkdf-sha256+ed25519";

  recipient_device_id: string;

  // DH keys (base64)
  ik_pub_b64: string;  // X25519 pub, 32B after decode
  spk_pub_b64: string; // X25519 pub, 32B after decode

  // Signature material (base64)
  ik_sig_pub_b64: string; // Ed25519 pub, 32B after decode
  spk_sig_b64: string;    // Ed25519 sig, 64B after decode

  // IDs
  spk_id: X3DHPrekeyId;

  // Optional OPK
  opk_pub_b64?: string; // X25519 pub, 32B after decode
  opk_id?: X3DHPrekeyId;
}

/**
 * X3DH session initialization message (wire format) v1.
 * Initiator includes spk_id always, and opk_id iff used_opk is true.
 */
export interface X3DHSessionInitV1 {
  v: 1;
  alg: "x3dh-x25519-hkdf-sha256+ed25519";

  sender_device_id: string;
  sender_ik_pub_b64: string; // X25519 pub, 32B after decode
  ek_pub_b64: string;        // X25519 pub, 32B after decode

  recipient_device_id: string;

  spk_id: X3DHPrekeyId;
  used_opk: boolean;
  opk_id?: X3DHPrekeyId;
}

/**
 * Validates that x is a structurally valid X3DHPrekeyBundleV1.
 * Does NOT validate base64 encoding or decoded key lengths.
 */
export function assertX3DHPrekeyBundleV1(
  x: unknown
): asserts x is X3DHPrekeyBundleV1 {
  if (typeof x !== "object" || x === null) {
    throw new TypeError("X3DHPrekeyBundleV1 must be an object");
  }
  const o = x as Record<string, unknown>;

  if (o.v !== 1) throw new TypeError("X3DHPrekeyBundleV1.v must be 1");
  if (o.alg !== "x3dh-x25519-hkdf-sha256+ed25519") {
    throw new TypeError(
      'X3DHPrekeyBundleV1.alg must be "x3dh-x25519-hkdf-sha256+ed25519"'
    );
  }

  if (typeof o.recipient_device_id !== "string") {
    throw new TypeError("X3DHPrekeyBundleV1.recipient_device_id must be a string");
  }

  for (const k of ["ik_pub_b64", "spk_pub_b64", "ik_sig_pub_b64", "spk_sig_b64"] as const) {
    if (typeof o[k] !== "string") {
      throw new TypeError(`X3DHPrekeyBundleV1.${k} must be a string`);
    }
  }

  if (o.spk_id === undefined || (typeof o.spk_id !== "number" && typeof o.spk_id !== "string")) {
    throw new TypeError("X3DHPrekeyBundleV1.spk_id must be a number or string");
  }

  if (o.opk_pub_b64 !== undefined && typeof o.opk_pub_b64 !== "string") {
    throw new TypeError("X3DHPrekeyBundleV1.opk_pub_b64 must be a string if provided");
  }
  if (o.opk_id !== undefined && typeof o.opk_id !== "number" && typeof o.opk_id !== "string") {
    throw new TypeError("X3DHPrekeyBundleV1.opk_id must be a number or string if provided");
  }

  // If opk_pub_b64 is present, opk_id must also be present (practical invariant)
  if (o.opk_pub_b64 !== undefined && o.opk_id === undefined) {
    throw new TypeError("X3DHPrekeyBundleV1.opk_id is required when opk_pub_b64 is provided");
  }
}

/**
 * Validates that x is a structurally valid X3DHSessionInitV1.
 * Does NOT validate base64 encoding or decoded key lengths.
 */
export function assertX3DHSessionInitV1(
  x: unknown
): asserts x is X3DHSessionInitV1 {
  if (typeof x !== "object" || x === null) {
    throw new TypeError("X3DHSessionInitV1 must be an object");
  }
  const o = x as Record<string, unknown>;

  if (o.v !== 1) throw new TypeError("X3DHSessionInitV1.v must be 1");
  if (o.alg !== "x3dh-x25519-hkdf-sha256+ed25519") {
    throw new TypeError(
      'X3DHSessionInitV1.alg must be "x3dh-x25519-hkdf-sha256+ed25519"'
    );
  }

  for (const k of ["sender_device_id", "sender_ik_pub_b64", "ek_pub_b64", "recipient_device_id"] as const) {
    if (typeof o[k] !== "string") {
      throw new TypeError(`X3DHSessionInitV1.${k} must be a string`);
    }
  }

  if (o.spk_id === undefined || (typeof o.spk_id !== "number" && typeof o.spk_id !== "string")) {
    throw new TypeError("X3DHSessionInitV1.spk_id must be a number or string");
  }

  if (typeof o.used_opk !== "boolean") {
    throw new TypeError("X3DHSessionInitV1.used_opk must be a boolean");
  }

  if (o.opk_id !== undefined && typeof o.opk_id !== "number" && typeof o.opk_id !== "string") {
    throw new TypeError("X3DHSessionInitV1.opk_id must be a number or string if provided");
  }

  if (o.used_opk === true && o.opk_id === undefined) {
    throw new TypeError("X3DHSessionInitV1.opk_id is required when used_opk is true");
  }
}

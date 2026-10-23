import { decodeStrictBase64 } from "../encoding/base64.js";
import { assertBoundedString, timingSafeEqual } from "../crypto/validation.js";
import { MAX_DEVICE_ID_BYTES } from "../crypto/limits.js";
import { IdentityMismatchError } from "../errors.js";

/**
 * A pinned identity for a single remote device.
 *
 * Two keys are pinned (safety-number semantics):
 * - ik_pub_b64:     X25519 identity key used for X3DH DH agreement.
 * - ik_sig_pub_b64: Ed25519 identity key used to sign signed prekeys.
 *
 * Pinning BOTH binds the DH identity to the signing identity; an attacker who
 * swaps either key is treated as a mismatch.
 */
export interface IdentityRecordV1 {
  device_id: string;
  ik_pub_b64: string;
  ik_sig_pub_b64: string;
  pinned_at_ms: number;
  last_seen_at_ms: number;
  /** True once a mismatching identity has been observed; cleared on a matching observation or approveRotation. */
  blocked_mismatch: boolean;
  /** The mismatching identity awaiting explicit operator approval. */
  pending_ik_pub_b64?: string;
  pending_ik_sig_pub_b64?: string;
  pending_seen_at_ms?: number;
}

/** Serializable snapshot of the whole registry (JSON / AsyncStorage friendly). */
export interface IdentityRegistryStateV1 {
  v: 1;
  records: Record<string, IdentityRecordV1>;
}

function decode32(label: string, b64: string): Uint8Array {
  const bytes = decodeStrictBase64(label, b64);
  if (bytes.byteLength !== 32) {
    throw new TypeError(`Invalid ${label} length: expected 32 bytes, got ${bytes.byteLength}`);
  }
  return bytes;
}

/** Every refusal names the field, never the stored value or the device id. */
function corrupt(field: string): never {
  throw new TypeError(`Corrupt identity state: ${field}`);
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** A stored key: canonical strict base64 of exactly 32 bytes. */
function storedKey32(field: string, v: unknown): string {
  if (typeof v !== "string") corrupt(field);
  let bytes: Uint8Array;
  try {
    bytes = decodeStrictBase64(field, v);
  } catch {
    corrupt(field);
  }
  if (bytes.byteLength !== 32) corrupt(field);
  return v;
}

function storedTime(field: string, v: unknown): number {
  if (typeof v !== "number" || !Number.isFinite(v) || v < 0) corrupt(field);
  return v;
}

/** One stored record, checked field by field; unknown fields are dropped. */
function readRecord(key: string, r: unknown): IdentityRecordV1 {
  if (!isPlainObject(r)) corrupt("record");
  if (r.device_id !== key) corrupt("device_id");
  try {
    assertBoundedString("device_id", key, MAX_DEVICE_ID_BYTES);
  } catch {
    corrupt("device_id");
  }
  if (typeof r.blocked_mismatch !== "boolean") corrupt("blocked_mismatch");
  const record: IdentityRecordV1 = {
    device_id: key,
    ik_pub_b64: storedKey32("ik_pub_b64", r.ik_pub_b64),
    ik_sig_pub_b64: storedKey32("ik_sig_pub_b64", r.ik_sig_pub_b64),
    pinned_at_ms: storedTime("pinned_at_ms", r.pinned_at_ms),
    last_seen_at_ms: storedTime("last_seen_at_ms", r.last_seen_at_ms),
    blocked_mismatch: r.blocked_mismatch,
  };
  // assertOrPin writes the three pending fields together and clears them together.
  if (r.pending_ik_pub_b64 !== undefined || r.pending_ik_sig_pub_b64 !== undefined || r.pending_seen_at_ms !== undefined) {
    record.pending_ik_pub_b64 = storedKey32("pending_ik_pub_b64", r.pending_ik_pub_b64);
    record.pending_ik_sig_pub_b64 = storedKey32("pending_ik_sig_pub_b64", r.pending_ik_sig_pub_b64);
    record.pending_seen_at_ms = storedTime("pending_seen_at_ms", r.pending_seen_at_ms);
  }
  return record;
}

/**
 * Trust-on-first-use registry with strong, two-key pinning.
 *
 * Semantics: an identity is pinned on first
 * contact and an identity CHANGE is never silently accepted. On a mismatch the
 * device is flagged `blocked_mismatch`, the observed keys are recorded as
 * `pending`, and an {@link IdentityMismatchError} is thrown. Re-keying only
 * takes effect through an explicit out-of-band {@link IdentityRegistry.approveRotation}
 * call (e.g. after the user re-verifies the safety number).
 *
 * State is fully serializable: {@link IdentityRegistry.exportState} writes it and
 * {@link IdentityRegistry.fromState} reads it back, checking every field.
 */
export class IdentityRegistry {
  private records = new Map<string, IdentityRecordV1>();

  /**
   * An empty registry. Passing `state` is the same as {@link fromState}, with the
   * same checks; it is kept so existing callers compile, and new code calls
   * `IdentityRegistry.fromState`.
   *
   * @deprecated with an argument: use {@link IdentityRegistry.fromState}
   * @throws TypeError "Corrupt identity state: <field>" as {@link fromState} does
   */
  constructor(state?: IdentityRegistryStateV1) {
    if (state !== undefined) {
      for (const record of IdentityRegistry.readState(state)) this.records.set(record.device_id, record);
    }
  }

  /**
   * Rebuilds a registry from {@link exportState}'s output. Stored state is
   * untrusted input: `v` must be 1; `records` an object whose every key equals its
   * record's `device_id` (a non-empty string of at most 256 UTF-8 bytes); both
   * keys canonical strict base64 of 32 bytes; the times finite numbers >= 0;
   * `blocked_mismatch` a boolean; the pending key pair and time all present and
   * valid, or all absent. Unknown fields are dropped.
   *
   * @throws TypeError "Corrupt identity state: <field>", never naming the stored
   *   value or a device id
   */
  static fromState(state: unknown): IdentityRegistry {
    const registry = new IdentityRegistry();
    for (const record of IdentityRegistry.readState(state)) registry.records.set(record.device_id, record);
    return registry;
  }

  private static readState(state: unknown): IdentityRecordV1[] {
    if (!isPlainObject(state)) corrupt("root");
    if (state.v !== 1) corrupt("v");
    if (!isPlainObject(state.records)) corrupt("records");
    return Object.entries(state.records).map(([key, record]) => readRecord(key, record));
  }

  /** Serializable snapshot for persistence. */
  exportState(): IdentityRegistryStateV1 {
    const records: Record<string, IdentityRecordV1> = {};
    for (const [device_id, record] of this.records) {
      records[device_id] = { ...record };
    }
    return { v: 1, records };
  }

  get(device_id: string): IdentityRecordV1 | null {
    return this.records.get(device_id) ?? null;
  }

  /** True if the device has a recorded, unresolved identity mismatch. */
  isBlocked(device_id: string): boolean {
    return this.records.get(device_id)?.blocked_mismatch ?? false;
  }

  /**
   * Compares an observed identity with the pinned one and records nothing:
   * `unknown` when the device has no pin, `match` when both keys equal the pinned
   * ones (byte for byte), `mismatch` otherwise. A host checks a setup's keys with
   * this before the message authenticates, and pins (or records a block) with
   * {@link assertOrPin} only after it does.
   */
  check(args: { device_id: string; ik_pub_b64: string; ik_sig_pub_b64: string }): "match" | "unknown" | "mismatch" {
    assertBoundedString("device_id", args.device_id, MAX_DEVICE_ID_BYTES);
    const ik = decode32("ik_pub_b64", args.ik_pub_b64);
    const ikSig = decode32("ik_sig_pub_b64", args.ik_sig_pub_b64);
    const existing = this.records.get(args.device_id);
    if (!existing) return "unknown";
    const ikMatches = timingSafeEqual(decode32("pinned ik_pub_b64", existing.ik_pub_b64), ik);
    const sigMatches = timingSafeEqual(
      decode32("pinned ik_sig_pub_b64", existing.ik_sig_pub_b64),
      ikSig
    );
    return ikMatches && sigMatches ? "match" : "mismatch";
  }

  /**
   * Pin on first use; verify on subsequent use.
   *
   * - First contact: pins both keys and returns `{ pinned_now: true }`.
   * - Match: refreshes `last_seen_at_ms`, clears any stale blocked/pending
   *   state, and returns `{ pinned_now: false }`.
   * - Mismatch: records the observed keys as `pending`, sets `blocked_mismatch`,
   *   and throws {@link IdentityMismatchError}. The pinned identity is NOT
   *   changed — use {@link approveRotation} to accept the new identity.
   */
  assertOrPin(args: {
    device_id: string;
    ik_pub_b64: string;
    ik_sig_pub_b64: string;
    now_ms?: number;
  }): { pinned_now: boolean } {
    assertBoundedString("device_id", args.device_id, MAX_DEVICE_ID_BYTES);
    const ik = decode32("ik_pub_b64", args.ik_pub_b64);
    const ikSig = decode32("ik_sig_pub_b64", args.ik_sig_pub_b64);
    const now = args.now_ms ?? Date.now();

    const existing = this.records.get(args.device_id);
    if (!existing) {
      this.records.set(args.device_id, {
        device_id: args.device_id,
        ik_pub_b64: args.ik_pub_b64,
        ik_sig_pub_b64: args.ik_sig_pub_b64,
        pinned_at_ms: now,
        last_seen_at_ms: now,
        blocked_mismatch: false,
      });
      return { pinned_now: true };
    }

    // Compare decoded bytes (representation-independent, constant-time).
    const ikMatches = timingSafeEqual(decode32("pinned ik_pub_b64", existing.ik_pub_b64), ik);
    const sigMatches = timingSafeEqual(
      decode32("pinned ik_sig_pub_b64", existing.ik_sig_pub_b64),
      ikSig
    );

    if (ikMatches && sigMatches) {
      existing.last_seen_at_ms = now;
      existing.blocked_mismatch = false;
      delete existing.pending_ik_pub_b64;
      delete existing.pending_ik_sig_pub_b64;
      delete existing.pending_seen_at_ms;
      return { pinned_now: false };
    }

    existing.blocked_mismatch = true;
    existing.pending_ik_pub_b64 = args.ik_pub_b64;
    existing.pending_ik_sig_pub_b64 = args.ik_sig_pub_b64;
    existing.pending_seen_at_ms = now;

    throw new IdentityMismatchError({
      deviceId: args.device_id,
      pinnedIkPubB64: existing.ik_pub_b64,
      observedIkPubB64: args.ik_pub_b64,
      pinnedIkSigPubB64: existing.ik_sig_pub_b64,
      observedIkSigPubB64: args.ik_sig_pub_b64,
    });
  }

  /**
   * Explicitly accept a new identity for a device (re-pin), clearing any
   * blocked/pending state. Call this only after the new identity has been
   * verified out of band (e.g. the user re-confirmed the safety number).
   */
  approveRotation(args: {
    device_id: string;
    ik_pub_b64: string;
    ik_sig_pub_b64: string;
    now_ms?: number;
  }): void {
    assertBoundedString("device_id", args.device_id, MAX_DEVICE_ID_BYTES);
    decode32("ik_pub_b64", args.ik_pub_b64);
    decode32("ik_sig_pub_b64", args.ik_sig_pub_b64);
    const now = args.now_ms ?? Date.now();

    this.records.set(args.device_id, {
      device_id: args.device_id,
      ik_pub_b64: args.ik_pub_b64,
      ik_sig_pub_b64: args.ik_sig_pub_b64,
      pinned_at_ms: now,
      last_seen_at_ms: now,
      blocked_mismatch: false,
    });
  }

  remove(device_id: string): void {
    this.records.delete(device_id);
  }
}

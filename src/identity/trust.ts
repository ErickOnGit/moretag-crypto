import { decodeStrictBase64 } from "../encoding/base64.js";
import { assertBoundedString, timingSafeEqual } from "../crypto/validation.js";
import { MAX_DEVICE_ID_BYTES } from "../crypto/limits.js";
import { IdentityMismatchError } from "../errors.js";

/**
 * A pinned identity for a single remote device.
 *
 * Two keys are pinned (Signal-style "safety number" semantics):
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

/**
 * Trust-on-first-use registry with strong, two-key pinning.
 *
 * Best-practice (Signal protocol) semantics: an identity is pinned on first
 * contact and an identity CHANGE is never silently accepted. On a mismatch the
 * device is flagged `blocked_mismatch`, the observed keys are recorded as
 * `pending`, and an {@link IdentityMismatchError} is thrown. Re-keying only
 * takes effect through an explicit out-of-band {@link IdentityRegistry.approveRotation}
 * call (e.g. after the user re-verifies the safety number).
 *
 * State is fully serializable via {@link IdentityRegistry.exportState} /
 * the `state` constructor argument for persistence across app restarts.
 */
export class IdentityRegistry {
  private records = new Map<string, IdentityRecordV1>();

  constructor(state?: IdentityRegistryStateV1) {
    if (state) {
      for (const [device_id, record] of Object.entries(state.records)) {
        this.records.set(device_id, { ...record });
      }
    }
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

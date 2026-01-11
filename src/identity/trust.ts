import { decodeX25519PubB64 } from "../crypto/x3dh.js";
import { assertBoundedString } from "../crypto/validation.js";
import { MAX_DEVICE_ID_BYTES } from "../crypto/limits.js";

export interface IdentityRecord {
  device_id: string;
  ik_pub_b64: string;
  added_at: number;
  updated_at: number;
  rotations: number;
}

export type TrustResult = "new" | "match" | "rotated";

export class IdentityRegistry {
  private records = new Map<string, IdentityRecord>();

  /**
   * Trust-on-first-use. If an identity is seen for the first time, it is pinned.
   * If seen again with the same key, it is accepted. If seen with a different key,
   * throw unless allowRotate is true, in which case it is pinned as a rotation.
   */
  trust(device_id: string, ik_pub_b64: string, opts?: { allowRotate?: boolean }): TrustResult {
    assertBoundedString("device_id", device_id, MAX_DEVICE_ID_BYTES);
    const ikBytes = decodeX25519PubB64(ik_pub_b64, "ik_pub_b64");
    const now = Date.now();

    const existing = this.records.get(device_id);
    if (!existing) {
      this.records.set(device_id, {
        device_id,
        ik_pub_b64,
        added_at: now,
        updated_at: now,
        rotations: 0,
      });
      // Prevent unused variable warning
      ikBytes.byteLength;
      return "new";
    }

    if (existing.ik_pub_b64 === ik_pub_b64) {
      return "match";
    }

    if (!opts?.allowRotate) {
      throw new Error(`Identity key mismatch for device ${device_id}`);
    }

    this.records.set(device_id, {
      ...existing,
      ik_pub_b64,
      updated_at: now,
      rotations: existing.rotations + 1,
    });
    // Prevent unused variable warning
    ikBytes.byteLength;
    return "rotated";
  }

  /**
   * Ensures the provided key matches the pinned identity.
   */
  assertTrusted(device_id: string, ik_pub_b64: string): void {
    const existing = this.records.get(device_id);
    if (!existing || existing.ik_pub_b64 !== ik_pub_b64) {
      throw new Error(`Untrusted identity for device ${device_id}`);
    }
  }

  get(device_id: string): IdentityRecord | undefined {
    return this.records.get(device_id);
  }

  remove(device_id: string): void {
    this.records.delete(device_id);
  }
}

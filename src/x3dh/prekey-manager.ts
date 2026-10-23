import type { X3DHPrekeyBundleV2 } from "../wire/x3dh.js";
import { X3DH_ALG_V2, isPrekeyId, MAX_PREKEY_ID } from "../wire/x3dh.js";
import { generateX25519Keypair } from "../crypto/x25519.js";
import { generateEd25519Keypair, ed25519Sign } from "../crypto/ed25519.js";
import { bytesToBase64, decodeStrictBase64 } from "../encoding/base64.js";
import { buildOpkBatchSigMessage, buildSpkSigMessage } from "../crypto/x3dh.js";
import { assertCanonicalDeviceId, isCanonicalDeviceId } from "../crypto/device-id.js";
import { UnknownPrekeyError } from "../errors.js";

export interface SignedPrekeyRecord {
  spk_id: number;
  priv32: Uint8Array;
  pub32: Uint8Array;
  created_at_ms: number;
}

export interface OneTimePrekeyRecord {
  opk_id: number;
  priv32: Uint8Array;
  pub32: Uint8Array;
  created_at_ms: number;
}

// --- Serializable (base64) state for persistence (JSON / AsyncStorage) --------

export interface SerializedSignedPrekeyV2 {
  spk_id: number;
  priv32_b64: string;
  pub32_b64: string;
  created_at_ms: number;
}

export interface SerializedOneTimePrekeyV2 {
  opk_id: number;
  priv32_b64: string;
  pub32_b64: string;
  created_at_ms: number;
}

/**
 * Serializable snapshot of an {@link X3DHPrekeyManagerV2}. Every signed prekey still
 * held is kept, so a responder can complete X3DH for a setup that named a
 * replaced one. Ids are integers 1..2^31-1; `next_opk_id` is above every
 * one-time prekey id the manager has minted.
 */
export interface X3DHPrekeyManagerStateV2 {
  v: 2;
  recipient_device_id: string;

  ik_x25519_priv_b64: string;
  ik_x25519_pub_b64: string;
  ik_ed25519_priv_b64: string;
  ik_ed25519_pub_b64: string;

  current_spk_id: number | null;
  spks: SerializedSignedPrekeyV2[];
  opks: SerializedOneTimePrekeyV2[];
  next_opk_id: number;
}

/** Every refusal names the field, never the stored value. */
function corrupt(field: string): never {
  throw new TypeError(`Corrupt prekey state: ${field}`);
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function key32(field: string, v: unknown): Uint8Array {
  if (typeof v !== "string") corrupt(field);
  let bytes: Uint8Array;
  try {
    bytes = decodeStrictBase64(field, v);
  } catch {
    corrupt(field);
  }
  if (bytes.byteLength !== 32) corrupt(field);
  return bytes;
}

function timestamp(field: string, v: unknown): number {
  if (typeof v !== "number" || !Number.isFinite(v)) corrupt(field);
  return v;
}

function copyPair(kp: { priv32: Uint8Array; pub32: Uint8Array }): { priv32: Uint8Array; pub32: Uint8Array } {
  return { priv32: new Uint8Array(kp.priv32), pub32: new Uint8Array(kp.pub32) };
}

/**
 * Per-device X3DH key material: the identity keys (X25519 for DH, Ed25519 for
 * signatures), signed prekeys and one-time prekeys, keyed by numeric id.
 *
 * Random draws: one 32-byte draw per key, in this order at creation (X25519
 * identity, Ed25519 identity, the first signed prekey, then one-time prekeys in id
 * order); one per signed-prekey rotation; one per minted one-time prekey, in id
 * order. One-time prekeys leave only through {@link removeOneTimePrekey}: reading
 * one for a setup does not consume it, so a host deletes it only after the first
 * message on that setup decrypts.
 */
export class X3DHPrekeyManagerV2 {
  readonly recipient_device_id: string;

  /** DH identity key (X25519). */
  readonly ik: { priv32: Uint8Array; pub32: Uint8Array };

  /** Signing identity key (Ed25519): signs signed prekeys and one-time prekey batches. */
  readonly ik_sig: { priv32: Uint8Array; pub32: Uint8Array };

  private spks = new Map<number, SignedPrekeyRecord>();
  private opks = new Map<number, OneTimePrekeyRecord>();
  private currentSpkId: number | null = null;
  private nextOpkId = 1;

  constructor(args: {
    recipient_device_id: string;
    ik?: { priv32: Uint8Array; pub32: Uint8Array };
    ik_sig?: { priv32: Uint8Array; pub32: Uint8Array };
  }) {
    assertCanonicalDeviceId(args.recipient_device_id);
    this.recipient_device_id = args.recipient_device_id;
    this.ik = args.ik ? copyPair(args.ik) : generateX25519Keypair();
    this.ik_sig = args.ik_sig ? copyPair(args.ik_sig) : generateEd25519Keypair();
  }

  /**
   * A ready-to-use manager: fresh identity keys, signed prekey 1 and
   * `initial_opk_count` one-time prekeys (none by default; a host mints them with
   * {@link mintOneTimePrekeys} when it publishes).
   */
  static create(args: {
    recipient_device_id: string;
    initial_opk_count?: number;
    now_ms?: number;
  }): X3DHPrekeyManagerV2 {
    const mgr = new X3DHPrekeyManagerV2({ recipient_device_id: args.recipient_device_id });
    mgr.rotateSignedPrekey(1, args.now_ms);
    mgr.mintOneTimePrekeys(args.initial_opk_count ?? 0, undefined, args.now_ms);
    return mgr;
  }

  /**
   * Rebuilds a manager from {@link exportState}'s snapshot. Stored state is
   * untrusted input: version, device id, 32-byte keys, ids in 1..2^31-1 without
   * duplicates, a current signed prekey that exists, and `next_opk_id` above every
   * one-time prekey id are checked; a refusal reads "Corrupt prekey state: <field>".
   */
  static fromState(state: X3DHPrekeyManagerStateV2): X3DHPrekeyManagerV2 {
    const s: unknown = state;
    if (!isPlainObject(s)) corrupt("root");
    if (s.v !== 2) corrupt("v");
    if (!isCanonicalDeviceId(s.recipient_device_id)) corrupt("recipient_device_id");

    const mgr = new X3DHPrekeyManagerV2({
      recipient_device_id: s.recipient_device_id,
      ik: {
        priv32: key32("ik_x25519_priv_b64", s.ik_x25519_priv_b64),
        pub32: key32("ik_x25519_pub_b64", s.ik_x25519_pub_b64),
      },
      ik_sig: {
        priv32: key32("ik_ed25519_priv_b64", s.ik_ed25519_priv_b64),
        pub32: key32("ik_ed25519_pub_b64", s.ik_ed25519_pub_b64),
      },
    });

    if (!Array.isArray(s.spks)) corrupt("spks");
    s.spks.forEach((spk: unknown, i: number) => {
      if (!isPlainObject(spk)) corrupt(`spks[${i}]`);
      if (!isPrekeyId(spk.spk_id)) corrupt(`spks[${i}].spk_id`);
      if (mgr.spks.has(spk.spk_id)) corrupt(`spks[${i}].spk_id (duplicate)`);
      mgr.spks.set(spk.spk_id, {
        spk_id: spk.spk_id,
        priv32: key32(`spks[${i}].priv32_b64`, spk.priv32_b64),
        pub32: key32(`spks[${i}].pub32_b64`, spk.pub32_b64),
        created_at_ms: timestamp(`spks[${i}].created_at_ms`, spk.created_at_ms),
      });
    });

    if (!Array.isArray(s.opks)) corrupt("opks");
    s.opks.forEach((opk: unknown, i: number) => {
      if (!isPlainObject(opk)) corrupt(`opks[${i}]`);
      if (!isPrekeyId(opk.opk_id)) corrupt(`opks[${i}].opk_id`);
      if (mgr.opks.has(opk.opk_id)) corrupt(`opks[${i}].opk_id (duplicate)`);
      mgr.opks.set(opk.opk_id, {
        opk_id: opk.opk_id,
        priv32: key32(`opks[${i}].priv32_b64`, opk.priv32_b64),
        pub32: key32(`opks[${i}].pub32_b64`, opk.pub32_b64),
        created_at_ms: timestamp(`opks[${i}].created_at_ms`, opk.created_at_ms),
      });
    });

    if (s.current_spk_id === null) {
      if (mgr.spks.size > 0) corrupt("current_spk_id");
    } else if (!isPrekeyId(s.current_spk_id) || !mgr.spks.has(s.current_spk_id)) {
      corrupt("current_spk_id");
    } else {
      mgr.currentSpkId = s.current_spk_id;
    }

    const next = s.next_opk_id;
    if (typeof next !== "number" || !Number.isSafeInteger(next) || next < 1 || next > MAX_PREKEY_ID + 1) {
      corrupt("next_opk_id");
    }
    for (const id of mgr.opks.keys()) if (id >= next) corrupt("next_opk_id");
    mgr.nextOpkId = next;
    return mgr;
  }

  /** Serializable snapshot for persistence; ids in ascending order. */
  exportState(): X3DHPrekeyManagerStateV2 {
    const byId = <T extends { created_at_ms: number }>(m: Map<number, T>): Array<[number, T]> =>
      Array.from(m.entries()).sort(([a], [b]) => a - b);
    return {
      v: 2,
      recipient_device_id: this.recipient_device_id,
      ik_x25519_priv_b64: bytesToBase64(this.ik.priv32),
      ik_x25519_pub_b64: bytesToBase64(this.ik.pub32),
      ik_ed25519_priv_b64: bytesToBase64(this.ik_sig.priv32),
      ik_ed25519_pub_b64: bytesToBase64(this.ik_sig.pub32),
      current_spk_id: this.currentSpkId,
      spks: byId(this.spks).map(([spk_id, rec]) => ({
        spk_id,
        priv32_b64: bytesToBase64(rec.priv32),
        pub32_b64: bytesToBase64(rec.pub32),
        created_at_ms: rec.created_at_ms,
      })),
      opks: byId(this.opks).map(([opk_id, rec]) => ({
        opk_id,
        priv32_b64: bytesToBase64(rec.priv32),
        pub32_b64: bytesToBase64(rec.pub32),
        created_at_ms: rec.created_at_ms,
      })),
      next_opk_id: this.nextOpkId,
    };
  }

  /**
   * Makes a new signed prekey current (one 32-byte draw). The id must be an
   * integer 1..2^31-1 above every signed prekey id held, so an id never names two
   * keys. Older signed prekeys are kept until {@link removeSignedPrekey}.
   */
  rotateSignedPrekey(spk_id: number, now_ms: number = Date.now()): SignedPrekeyRecord {
    if (!isPrekeyId(spk_id)) throw new RangeError("spk_id must be an integer 1..2^31-1");
    for (const id of this.spks.keys()) {
      if (id >= spk_id) throw new RangeError("spk_id must be above every signed prekey id held");
    }
    const kp = generateX25519Keypair();
    const rec: SignedPrekeyRecord = { spk_id, priv32: kp.priv32, pub32: kp.pub32, created_at_ms: now_ms };
    this.spks.set(spk_id, rec);
    this.currentSpkId = spk_id;
    return { ...rec, priv32: new Uint8Array(rec.priv32), pub32: new Uint8Array(rec.pub32) };
  }

  /** Deletes a replaced signed prekey; idempotent. The current one cannot be removed. */
  removeSignedPrekey(spk_id: number): void {
    if (spk_id === this.currentSpkId) throw new Error("The current signed prekey cannot be removed");
    this.spks.delete(spk_id);
  }

  /** Age of the current signed prekey against `max_age_ms`. */
  shouldRotateSignedPrekey(max_age_ms: number, now_ms: number = Date.now()): boolean {
    if (!Number.isFinite(max_age_ms) || max_age_ms <= 0) return false;
    if (this.currentSpkId === null) return true;
    const rec = this.spks.get(this.currentSpkId);
    if (!rec) return true;
    return now_ms - rec.created_at_ms >= max_age_ms;
  }

  /** The current signed prekey (a copy). */
  getCurrentSignedPrekey(): SignedPrekeyRecord {
    if (this.currentSpkId === null) {
      throw new Error("No signed prekey available; call rotateSignedPrekey(spk_id)");
    }
    return this.getSignedPrekey(this.currentSpkId);
  }

  /** A held signed prekey (a copy). Throws {@link UnknownPrekeyError} `unknown_spk`. */
  getSignedPrekey(spk_id: number): SignedPrekeyRecord {
    const rec = this.spks.get(spk_id);
    if (!rec) throw new UnknownPrekeyError("unknown_spk");
    return { ...rec, priv32: new Uint8Array(rec.priv32), pub32: new Uint8Array(rec.pub32) };
  }

  /** A held signed prekey's private key (a copy). Throws `unknown_spk`. */
  getSignedPrekeyPriv32(spk_id: number): Uint8Array {
    return this.getSignedPrekey(spk_id).priv32;
  }

  /**
   * Mints `count` one-time prekeys with consecutive ids starting at
   * max(next_opk_id, minNextId), one 32-byte draw each in id order. A host passes
   * the server's high-water mark + 1 as `minNextId`, so an id the server has seen
   * is never reused. Returns copies of the new records.
   */
  mintOneTimePrekeys(count: number, minNextId?: number, now_ms: number = Date.now()): OneTimePrekeyRecord[] {
    if (!Number.isSafeInteger(count) || count < 0) throw new RangeError("count must be a non-negative integer");
    if (minNextId !== undefined && !isPrekeyId(minNextId)) {
      throw new RangeError("minNextId must be an integer 1..2^31-1");
    }
    const start = Math.max(this.nextOpkId, minNextId ?? 1);
    if (start + count - 1 > MAX_PREKEY_ID) throw new RangeError("One-time prekey ids exhausted");
    const out: OneTimePrekeyRecord[] = [];
    for (let i = 0; i < count; i++) {
      const opk_id = start + i;
      const kp = generateX25519Keypair();
      const rec: OneTimePrekeyRecord = { opk_id, priv32: kp.priv32, pub32: kp.pub32, created_at_ms: now_ms };
      this.opks.set(opk_id, rec);
      out.push({ ...rec, priv32: new Uint8Array(rec.priv32), pub32: new Uint8Array(rec.pub32) });
    }
    this.nextOpkId = Math.max(this.nextOpkId, start + count);
    return out;
  }

  /** Held one-time prekeys with an id above `opk_id`, ascending (copies of the public part). */
  listOneTimePrekeysAbove(opk_id: number): Array<{ opk_id: number; pub32: Uint8Array; created_at_ms: number }> {
    return Array.from(this.opks.values())
      .filter((rec) => rec.opk_id > opk_id)
      .sort((a, b) => a.opk_id - b.opk_id)
      .map((rec) => ({ opk_id: rec.opk_id, pub32: new Uint8Array(rec.pub32), created_at_ms: rec.created_at_ms }));
  }

  /** A held one-time prekey's private key (a copy), without consuming it. Throws `unknown_opk`. */
  getOneTimePrekeyPriv32(opk_id: number): Uint8Array {
    const rec = this.opks.get(opk_id);
    if (!rec) throw new UnknownPrekeyError("unknown_opk");
    return new Uint8Array(rec.priv32);
  }

  /** True when the one-time prekey is still held. */
  hasOneTimePrekey(opk_id: number): boolean {
    return this.opks.has(opk_id);
  }

  /** Deletes a one-time prekey; idempotent. Returns whether it was held. */
  removeOneTimePrekey(opk_id: number): boolean {
    return this.opks.delete(opk_id);
  }

  getOneTimePrekeyCount(): number {
    return this.opks.size;
  }

  /**
   * The signed-prekey bundle this device publishes: identity keys, the current
   * signed prekey and its signature. No one-time prekey: the server hands those out
   * one per bundle.
   */
  getPrekeyBundle(): X3DHPrekeyBundleV2 {
    const spk = this.getCurrentSignedPrekey();
    const sigMsg = buildSpkSigMessage({
      recipient_device_id: this.recipient_device_id,
      ik_pub32: this.ik.pub32,
      spk_pub32: spk.pub32,
      spk_id: spk.spk_id,
    });
    return {
      v: 2,
      alg: X3DH_ALG_V2,
      recipient_device_id: this.recipient_device_id,
      ik_pub_b64: bytesToBase64(this.ik.pub32),
      ik_sig_pub_b64: bytesToBase64(this.ik_sig.pub32),
      spk_pub_b64: bytesToBase64(spk.pub32),
      spk_id: spk.spk_id,
      spk_sig_b64: bytesToBase64(ed25519Sign(this.ik_sig.priv32, sigMsg)),
    };
  }

  /**
   * Signs a batch of held one-time prekeys for publication: Ed25519 by the identity
   * signing key over CBOR ["moretag/x3dh/opk-batch/v1", device_id, [[id, key], ...]]
   * in the order given. Throws `unknown_opk` for an id not held.
   */
  signOneTimePrekeyBatch(opk_ids: readonly number[]): {
    prekeys: Array<{ opk_id: number; pub_b64: string }>;
    batch_sig_b64: string;
  } {
    if (opk_ids.length === 0) throw new RangeError("A batch needs at least one one-time prekey");
    const prekeys = opk_ids.map((opk_id) => {
      const rec = this.opks.get(opk_id);
      if (!rec) throw new UnknownPrekeyError("unknown_opk");
      return { opk_id, pub32: rec.pub32 };
    });
    const message = buildOpkBatchSigMessage({ device_id: this.recipient_device_id, prekeys });
    return {
      prekeys: prekeys.map((p) => ({ opk_id: p.opk_id, pub_b64: bytesToBase64(p.pub32) })),
      batch_sig_b64: bytesToBase64(ed25519Sign(this.ik_sig.priv32, message)),
    };
  }
}

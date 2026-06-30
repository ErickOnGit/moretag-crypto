import type { X3DHPrekeyBundleV1, X3DHPrekeyId } from "../wire/x3dh.js";
import { generateX25519Keypair } from "../crypto/x25519.js";
import { generateEd25519Keypair, ed25519Sign } from "../crypto/ed25519.js";
import { bytesToBase64, decodeStrictBase64 } from "../encoding/base64.js";
import { buildSpkSigMessage } from "../crypto/x3dh.js";

export interface SignedPrekeyRecord {
  spk_id: X3DHPrekeyId;
  priv32: Uint8Array;
  pub32: Uint8Array;
  created_at_ms: number;
}

export interface OneTimePrekeyRecord {
  opk_id: X3DHPrekeyId;
  priv32: Uint8Array;
  pub32: Uint8Array;
  created_at_ms: number;
}

// --- Serializable (base64) state for persistence (JSON / AsyncStorage) --------

export interface SerializedSignedPrekeyV1 {
  spk_id: X3DHPrekeyId;
  priv32_b64: string;
  pub32_b64: string;
  created_at_ms: number;
}

export interface SerializedOneTimePrekeyV1 {
  opk_id: X3DHPrekeyId;
  priv32_b64: string;
  pub32_b64: string;
  created_at_ms: number;
}

/**
 * Fully serializable snapshot of an {@link X3DHPrekeyManagerV1}. Unlike a single
 * "current prekey" snapshot, ALL signed prekeys are retained so a responder can
 * still complete X3DH for a session that referenced a now-rotated SPK.
 */
export interface X3DHPrekeyManagerStateV1 {
  v: 1;
  recipient_device_id: string;

  ik_x25519_priv_b64: string;
  ik_x25519_pub_b64: string;
  ik_ed25519_priv_b64: string;
  ik_ed25519_pub_b64: string;

  current_spk_id?: X3DHPrekeyId | undefined;
  spks: SerializedSignedPrekeyV1[];
  opks: SerializedOneTimePrekeyV1[];
  next_opk_id: number;
}

function decodePriv32(label: string, b64: string): Uint8Array {
  const bytes = decodeStrictBase64(label, b64);
  if (bytes.byteLength !== 32) {
    throw new TypeError(`Invalid ${label} length: expected 32 bytes, got ${bytes.byteLength}`);
  }
  return bytes;
}

/**
 * Manages per-device X3DH key material: identity keys, signed prekeys, and one-time prekeys.
 * This is a storage-oriented helper; persist the fields you need in your app layer.
 */
export class X3DHPrekeyManagerV1 {
  readonly recipient_device_id: string;

  // DH identity key (X25519)
  readonly ik: { priv32: Uint8Array; pub32: Uint8Array };

  // Signing identity key (Ed25519) for SPK signatures
  readonly ik_sig: { priv32: Uint8Array; pub32: Uint8Array };

  private spks = new Map<string, SignedPrekeyRecord>();
  private opks = new Map<string, OneTimePrekeyRecord>();

  private currentSpkId: X3DHPrekeyId | undefined = undefined;

  // Monotonic counter used by refillOneTimePrekeys() to mint fresh numeric ids.
  private nextOpkId = 1;

  constructor(args: {
    recipient_device_id: string;
    ik?: { priv32: Uint8Array; pub32: Uint8Array };
    ik_sig?: { priv32: Uint8Array; pub32: Uint8Array };
  }) {
    this.recipient_device_id = args.recipient_device_id;
    this.ik = args.ik ?? generateX25519Keypair();
    this.ik_sig = args.ik_sig ?? generateEd25519Keypair();
  }

  /**
   * Creates a ready-to-use manager: fresh identity keys, one initial signed
   * prekey (id 1), and `initial_opk_count` one-time prekeys.
   */
  static create(args: {
    recipient_device_id: string;
    initial_opk_count?: number;
    now_ms?: number;
  }): X3DHPrekeyManagerV1 {
    const mgr = new X3DHPrekeyManagerV1({ recipient_device_id: args.recipient_device_id });
    mgr.rotateSignedPrekey(1, args.now_ms);
    mgr.refillOneTimePrekeys(Math.max(args.initial_opk_count ?? 100, 0), args.now_ms);
    return mgr;
  }

  /** Rebuilds a manager from a serialized snapshot (see {@link exportState}). */
  static fromState(state: X3DHPrekeyManagerStateV1): X3DHPrekeyManagerV1 {
    if (state.v !== 1) throw new TypeError("Unsupported X3DHPrekeyManagerStateV1 version");

    const mgr = new X3DHPrekeyManagerV1({
      recipient_device_id: state.recipient_device_id,
      ik: {
        priv32: decodePriv32("ik_x25519_priv_b64", state.ik_x25519_priv_b64),
        pub32: decodePriv32("ik_x25519_pub_b64", state.ik_x25519_pub_b64),
      },
      ik_sig: {
        priv32: decodePriv32("ik_ed25519_priv_b64", state.ik_ed25519_priv_b64),
        pub32: decodePriv32("ik_ed25519_pub_b64", state.ik_ed25519_pub_b64),
      },
    });

    for (const spk of state.spks) {
      mgr.spks.set(String(spk.spk_id), {
        spk_id: spk.spk_id,
        priv32: decodePriv32("spk priv32", spk.priv32_b64),
        pub32: decodePriv32("spk pub32", spk.pub32_b64),
        created_at_ms: spk.created_at_ms,
      });
    }
    for (const opk of state.opks) {
      mgr.opks.set(String(opk.opk_id), {
        opk_id: opk.opk_id,
        priv32: decodePriv32("opk priv32", opk.priv32_b64),
        pub32: decodePriv32("opk pub32", opk.pub32_b64),
        created_at_ms: opk.created_at_ms,
      });
    }
    mgr.currentSpkId = state.current_spk_id;
    mgr.nextOpkId = state.next_opk_id;
    return mgr;
  }

  /** Serializable snapshot for persistence. */
  exportState(): X3DHPrekeyManagerStateV1 {
    const spks: SerializedSignedPrekeyV1[] = [];
    for (const rec of this.spks.values()) {
      spks.push({
        spk_id: rec.spk_id,
        priv32_b64: bytesToBase64(rec.priv32),
        pub32_b64: bytesToBase64(rec.pub32),
        created_at_ms: rec.created_at_ms,
      });
    }
    const opks: SerializedOneTimePrekeyV1[] = [];
    for (const rec of this.opks.values()) {
      opks.push({
        opk_id: rec.opk_id,
        priv32_b64: bytesToBase64(rec.priv32),
        pub32_b64: bytesToBase64(rec.pub32),
        created_at_ms: rec.created_at_ms,
      });
    }
    return {
      v: 1,
      recipient_device_id: this.recipient_device_id,
      ik_x25519_priv_b64: bytesToBase64(this.ik.priv32),
      ik_x25519_pub_b64: bytesToBase64(this.ik.pub32),
      ik_ed25519_priv_b64: bytesToBase64(this.ik_sig.priv32),
      ik_ed25519_pub_b64: bytesToBase64(this.ik_sig.pub32),
      current_spk_id: this.currentSpkId,
      spks,
      opks,
      next_opk_id: this.nextOpkId,
    };
  }

  rotateSignedPrekey(spk_id: X3DHPrekeyId, now_ms: number = Date.now()): SignedPrekeyRecord {
    const kp = generateX25519Keypair();
    const rec: SignedPrekeyRecord = {
      spk_id,
      priv32: kp.priv32,
      pub32: kp.pub32,
      created_at_ms: now_ms,
    };
    this.spks.set(String(spk_id), rec);
    this.currentSpkId = spk_id;
    return rec;
  }

  /** Age of the current signed prekey vs `max_age_ms`. */
  shouldRotateSignedPrekey(max_age_ms: number, now_ms: number = Date.now()): boolean {
    if (!Number.isFinite(max_age_ms) || max_age_ms <= 0) return false;
    if (this.currentSpkId === undefined) return true;
    const rec = this.spks.get(String(this.currentSpkId));
    if (!rec) return true;
    return now_ms - rec.created_at_ms >= max_age_ms;
  }

  getCurrentSignedPrekey(): SignedPrekeyRecord {
    if (this.currentSpkId === undefined) {
      throw new Error("No signed prekey available; call rotateSignedPrekey(spk_id)");
    }
    const rec = this.spks.get(String(this.currentSpkId));
    if (!rec) throw new Error("Current signed prekey missing");
    return rec;
  }

  addOneTimePrekeys(args: { startId: number; count: number; now_ms?: number }): OneTimePrekeyRecord[] {
    const now = args.now_ms ?? Date.now();
    const out: OneTimePrekeyRecord[] = [];
    for (let i = 0; i < args.count; i++) {
      const opk_id = args.startId + i;
      const kp = generateX25519Keypair();
      const rec: OneTimePrekeyRecord = {
        opk_id,
        priv32: kp.priv32,
        pub32: kp.pub32,
        created_at_ms: now,
      };
      this.opks.set(String(opk_id), rec);
      out.push(rec);
    }
    // Keep the auto-id counter ahead of any explicitly supplied ids.
    this.nextOpkId = Math.max(this.nextOpkId, args.startId + args.count);
    return out;
  }

  /**
   * Mints `count` new one-time prekeys using the internal monotonic id counter
   * (no id bookkeeping required by the caller). Returns the new records.
   */
  refillOneTimePrekeys(count: number, now_ms: number = Date.now()): OneTimePrekeyRecord[] {
    const normalized = Math.max(Math.floor(count), 0);
    const out: OneTimePrekeyRecord[] = [];
    for (let i = 0; i < normalized; i++) {
      const opk_id = this.nextOpkId;
      const kp = generateX25519Keypair();
      const rec: OneTimePrekeyRecord = {
        opk_id,
        priv32: kp.priv32,
        pub32: kp.pub32,
        created_at_ms: now_ms,
      };
      this.opks.set(String(opk_id), rec);
      this.nextOpkId += 1;
      out.push(rec);
    }
    return out;
  }

  getOneTimePrekeyCount(): number {
    return this.opks.size;
  }

  /** True when the remaining one-time prekey count has fallen to/below `threshold`. */
  shouldRefillOneTimePrekeys(threshold: number): boolean {
    return this.opks.size <= Math.max(Math.floor(threshold), 0);
  }

  hasOneTimePrekeys(): boolean {
    return this.opks.size > 0;
  }

  peekOneTimePrekey(): OneTimePrekeyRecord | undefined {
    const first = this.opks.values().next();
    return first.done ? undefined : first.value;
  }

  consumeOneTimePrekey(opk_id: X3DHPrekeyId): OneTimePrekeyRecord {
    const key = String(opk_id);
    const rec = this.opks.get(key);
    if (!rec) throw new Error(`Unknown opk_id: ${String(opk_id)}`);
    this.opks.delete(key);
    return rec;
  }

  getSignedPrekeyPriv32(spk_id: X3DHPrekeyId): Uint8Array {
    const rec = this.spks.get(String(spk_id));
    if (!rec) throw new Error(`Unknown spk_id: ${String(spk_id)}`);
    return rec.priv32;
  }

  getOneTimePrekeyPriv32(opk_id: X3DHPrekeyId): Uint8Array {
    const rec = this.opks.get(String(opk_id));
    if (!rec) throw new Error(`Unknown opk_id: ${String(opk_id)}`);
    return rec.priv32;
  }

  /**
   * Constructs a signed prekey bundle for publication.
   * If an OPK is available, includes one OPK (but does not consume it).
   */
  getPrekeyBundle(): X3DHPrekeyBundleV1 {
    const spk = this.getCurrentSignedPrekey();

    const sigMsg = buildSpkSigMessage({
      recipient_device_id: this.recipient_device_id,
      ik_pub32: this.ik.pub32,
      spk_pub32: spk.pub32,
      spk_id: spk.spk_id,
    });
    const spk_sig64 = ed25519Sign(this.ik_sig.priv32, sigMsg);

    const bundle: X3DHPrekeyBundleV1 = {
      v: 1,
      alg: "x3dh-x25519-hkdf-sha256+ed25519",
      recipient_device_id: this.recipient_device_id,
      ik_pub_b64: bytesToBase64(this.ik.pub32),
      spk_pub_b64: bytesToBase64(spk.pub32),
      ik_sig_pub_b64: bytesToBase64(this.ik_sig.pub32),
      spk_sig_b64: bytesToBase64(spk_sig64),
      spk_id: spk.spk_id,
    };

    const opk = this.peekOneTimePrekey();
    if (opk) {
      bundle.opk_pub_b64 = bytesToBase64(opk.pub32);
      bundle.opk_id = opk.opk_id;
    }

    return bundle;
  }
}


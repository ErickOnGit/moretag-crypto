import type { X3DHPrekeyBundleV1, X3DHPrekeyId } from "../wire/x3dh.js";
import { generateX25519Keypair } from "../crypto/x25519.js";
import { generateEd25519Keypair, ed25519Sign } from "../crypto/ed25519.js";
import { bytesToBase64 } from "../encoding/base64.js";
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

  private currentSpkId?: X3DHPrekeyId;

  constructor(args: {
    recipient_device_id: string;
    ik?: { priv32: Uint8Array; pub32: Uint8Array };
    ik_sig?: { priv32: Uint8Array; pub32: Uint8Array };
  }) {
    this.recipient_device_id = args.recipient_device_id;
    this.ik = args.ik ?? generateX25519Keypair();
    this.ik_sig = args.ik_sig ?? generateEd25519Keypair();
  }

  rotateSignedPrekey(spk_id: X3DHPrekeyId): SignedPrekeyRecord {
    const kp = generateX25519Keypair();
    const rec: SignedPrekeyRecord = {
      spk_id,
      priv32: kp.priv32,
      pub32: kp.pub32,
      created_at_ms: Date.now(),
    };
    this.spks.set(String(spk_id), rec);
    this.currentSpkId = spk_id;
    return rec;
  }

  getCurrentSignedPrekey(): SignedPrekeyRecord {
    if (this.currentSpkId === undefined) {
      throw new Error("No signed prekey available; call rotateSignedPrekey(spk_id)");
    }
    const rec = this.spks.get(String(this.currentSpkId));
    if (!rec) throw new Error("Current signed prekey missing");
    return rec;
  }

  addOneTimePrekeys(args: { startId: number; count: number }): OneTimePrekeyRecord[] {
    const out: OneTimePrekeyRecord[] = [];
    for (let i = 0; i < args.count; i++) {
      const opk_id = args.startId + i;
      const kp = generateX25519Keypair();
      const rec: OneTimePrekeyRecord = {
        opk_id,
        priv32: kp.priv32,
        pub32: kp.pub32,
        created_at_ms: Date.now(),
      };
      this.opks.set(String(opk_id), rec);
      out.push(rec);
    }
    return out;
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


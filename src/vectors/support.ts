/**
 * Support for the vector tests (not part of the build): loading the files, the
 * providers each vector runs on, scripted randomness, and the mapping between the
 * vector files' own field names and layouts and the library's.
 *
 * The vector files were written by an author who read no library source; their
 * JSON field names, role names and skipped-key layout are that author's own and not
 * normative. Only the bytes that enter a KDF, a signature or an AEAD are. So the
 * files stay as they are and every name is mapped here.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";
import * as nodeCrypto from "node:crypto";
import {
  registerCryptoPrimitives,
  resetCryptoPrimitives,
  type CryptoPrimitivesProvider,
} from "../crypto/primitives.js";
import { createNodeCryptoPrimitives, type NodeCryptoLike } from "../providers/node-crypto.js";
import { bytesToBase64, decodeStrictBase64 } from "../encoding/base64.js";
import { X3DH_ALG_V2 } from "../wire/x3dh.js";
import type { HeaderProtoV2 } from "../wire/header.js";
import type { SerializedRatchetStateV2 } from "../ratchet/serialization.js";
import { X3DHPrekeyManagerV2 } from "../x3dh/prekey-manager.js";

export function loadVector(name: string): any {
  return JSON.parse(readFileSync(join(process.cwd(), "vectors", name), "utf-8"));
}

export function unhex(hex: string): Uint8Array {
  if (!/^([0-9a-f]{2})*$/.test(hex)) throw new Error("not lowercase hex");
  return new Uint8Array(Buffer.from(hex, "hex"));
}

export const hex = (b: Uint8Array): string => Buffer.from(b).toString("hex");
export const hexToB64 = (h: string): string => bytesToBase64(unhex(h));

/** The providers every vector runs on: the built-in @noble, and node:crypto through the adapter. */
export const PROVIDERS: Array<{ name: string; make: () => Omit<CryptoPrimitivesProvider, "randomBytes" | "name"> }> = [
  { name: "noble", make: () => ({}) },
  {
    name: "node:crypto",
    make: () => {
      const { name: _name, randomBytes: _rb, ...rest } = createNodeCryptoPrimitives(
        nodeCrypto as unknown as NodeCryptoLike,
        { name: "node:crypto" }
      );
      return rest;
    },
  },
];

/**
 * Registers a provider whose randomBytes is real until a queue is loaded, then
 * returns copies of the queued draws in order, throwing on a wrong length or an
 * empty queue. The registration self-test draws real randomness before any queue.
 */
export function scriptedRandomness(providerName: string): {
  load(draws: Array<{ hex: string; length: number }>): void;
  remaining(): number;
  release(): void;
} {
  let queue: Uint8Array[] | null = null;
  const base = PROVIDERS.find((p) => p.name === providerName)!.make();
  registerCryptoPrimitives({
    ...base,
    name: `scripted ${providerName}`,
    randomBytes: (n: number) => {
      if (queue === null) return new Uint8Array(nodeCrypto.randomBytes(n));
      const next = queue.shift();
      if (next === undefined) throw new Error("scripted randomness: the queue is empty");
      if (next.length !== n) throw new Error(`scripted randomness: ${n} bytes asked, ${next.length} queued`);
      return next.slice();
    },
  });
  return {
    load(draws) {
      queue = draws.map((d) => {
        const bytes = unhex(d.hex);
        if (bytes.length !== d.length) throw new Error("draw length does not match its bytes");
        return bytes;
      });
    },
    remaining: () => queue?.length ?? 0,
    release() {
      queue = null;
    },
  };
}

export function resetProviders(): void {
  resetCryptoPrimitives();
}

// --- Name mapping between the vector files and the library ------------------------

/**
 * The vectors' valid bundles and session_inits carry no `alg`: no text the author
 * could read gives its value. The library's carry the unchanged v2 string, added
 * here and never in the files. A refusal vector that carries its own `alg`
 * (bundle_alg_unknown, bundle_alg_empty) keeps it, since the wire value wins.
 */
export function libraryBundle(wire: Record<string, unknown>): any {
  return { alg: X3DH_ALG_V2, ...wire };
}

export function librarySessionInit(wire: Record<string, unknown>): any {
  return { alg: X3DH_ALG_V2, ...wire };
}

/** The vectors' header is flat (dh_pub_b64, pn, n at the top); the library nests them under `dr`. */
export function libraryHeader(w: Record<string, unknown>): HeaderProtoV2 {
  return {
    v: w.v,
    alg: w.alg,
    nonce_b64: w.nonce_b64,
    sender_device_id: w.sender_device_id,
    recipient_device_id: w.recipient_device_id,
    dr: { dh_pub_b64: w.dh_pub_b64, pn: w.pn, n: w.n },
    ...("grp" in w ? { grp: w.grp } : {}),
  } as HeaderProtoV2;
}

export function vectorHeader(h: HeaderProtoV2): Record<string, unknown> {
  return {
    v: h.v,
    alg: h.alg,
    nonce_b64: h.nonce_b64,
    sender_device_id: h.sender_device_id,
    recipient_device_id: h.recipient_device_id,
    dh_pub_b64: h.dr.dh_pub_b64,
    pn: h.dr.pn,
    n: h.dr.n,
    ...(h.grp ? { grp: h.grp } : {}),
  };
}

/**
 * X25519 clamps the private scalar inside (RFC 7748 §5). The vector author stores
 * the raw 32-byte draw; the library stores it clamped. Both give the same key.
 */
function clampB64(b64: string): string {
  const k = decodeStrictBase64("priv", b64);
  k[0] = k[0]! & 248;
  k[31] = (k[31]! & 127) | 64;
  return bytesToBase64(k);
}

/** A vector state in the library's serialized form (skipped as [id, mk] pairs). */
export function libraryState(v: any): SerializedRatchetStateV2 {
  return {
    v: v.v,
    role: v.role,
    ad_b64: v.ad_b64,
    rk32_b64: v.rk32_b64,
    ck_s32_b64: v.ck_s32_b64,
    ck_r32_b64: v.ck_r32_b64,
    ns: v.ns,
    nr: v.nr,
    pn: v.pn,
    dh_self: { priv32_b64: v.dh_self.priv32_b64, pub32_b64: v.dh_self.pub32_b64 },
    dh_remote_pub32_b64: v.dh_remote_pub32_b64,
    skipped: v.skipped.map((e: any) => [`${e.dh_pub32_b64}:${e.n}`, e.mk32_b64]),
  };
}

/** Both sides' serialized states, normalized for comparison (the private scalar clamped). */
export function comparable(s: SerializedRatchetStateV2): SerializedRatchetStateV2 {
  return { ...s, dh_self: { ...s.dh_self, priv32_b64: clampB64(s.dh_self.priv32_b64) } };
}

/** A prekey manager holding a vector party's keys. */
export function partyPrekeys(
  party: any,
  held: { spk_ids?: number[]; opk_ids?: number[] } = {}
): X3DHPrekeyManagerV2 {
  const spks = party.spk && (held.spk_ids ?? [party.spk.id]).includes(party.spk.id) ? [party.spk] : [];
  const opks = party.opk && (held.opk_ids ?? [party.opk.id]).includes(party.opk.id) ? [party.opk] : [];
  return X3DHPrekeyManagerV2.fromState({
    v: 2,
    recipient_device_id: party.device_id,
    ik_x25519_priv_b64: hexToB64(party.ik.private_hex),
    ik_x25519_pub_b64: hexToB64(party.ik.public_hex),
    ik_ed25519_priv_b64: hexToB64(party.ik_sig.seed_hex),
    ik_ed25519_pub_b64: hexToB64(party.ik_sig.public_hex),
    current_spk_id: spks.length ? party.spk.id : null,
    spks: spks.map((k: any) => ({ spk_id: k.id, priv32_b64: hexToB64(k.private_hex), pub32_b64: hexToB64(k.public_hex), created_at_ms: 0 })),
    opks: opks.map((k: any) => ({ opk_id: k.id, priv32_b64: hexToB64(k.private_hex), pub32_b64: hexToB64(k.public_hex), created_at_ms: 0 })),
    next_opk_id: (party.opk?.id ?? 0) + 1,
  });
}

/** Runs fn and returns what it threw (or fails when it returns). */
export function thrownBy(fn: () => unknown): any {
  try {
    fn();
  } catch (err) {
    return err;
  }
  throw new Error("expected a refusal");
}

import { describe, it, expect, afterEach, vi } from "vitest";
import { wipe } from "./wipe.js";
import { getPrimitives, registerCryptoPrimitives, resetCryptoPrimitives } from "./primitives.js";
import { kdfChainKey, kdfRootAndChainKey } from "./kdf.js";
import { x3dhResponderV2 } from "./x3dh.js";
import { sealLocalV2, openLocalV2, buildSelfSealAadV2 } from "./seal.js";
import { randomBytes } from "@noble/ciphers/utils.js";
import {
  ratchetDecrypt,
  ratchetEncrypt,
  ratchetInitResponderV2,
  type RatchetState,
} from "../ratchet/ratchet.js";
import { serializeRatchetStateV2 } from "../ratchet/serialization.js";
import { x3dhInitiatorBootstrapV2, x3dhResponderBootstrapV2 } from "../x3dh/session.js";
import { X3DHPrekeyManagerV2 } from "../x3dh/prekey-manager.js";
import { IdentityRegistry } from "../identity/trust.js";
import { DecryptFailedError } from "../errors.js";
import { bytesToBase64 } from "../encoding/base64.js";
import { MAX_SKIP_DERIVE, MAX_SKIPPED_KEYS } from "./limits.js";
import { ALICE_DEVICE, BOB_DEVICE, establishedPair, sessionPair, utf8 } from "../test-fixtures.js";

// Every array the library's wipe() is given, with its bytes just before zeroing,
// so a test can find an internal copy (a decrypt's working copy) by what it held.
// The real wipe still runs.
const wipes = vi.hoisted(() => ({ log: [] as Array<{ array: Uint8Array; before: Uint8Array }> }));
vi.mock("./wipe.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./wipe.js")>();
  return {
    ...actual,
    wipe: (...arrays: Array<Uint8Array | null | undefined>) => {
      for (const a of arrays) if (a) wipes.log.push({ array: a, before: a.slice() });
      actual.wipe(...arrays);
    },
  };
});

afterEach(() => resetCryptoPrimitives());

const isZero = (b: Uint8Array) => b.every((x) => x === 0);
const snapshot = (s: Parameters<typeof serializeRatchetStateV2>[0]) => JSON.stringify(serializeRatchetStateV2(s));
const sameBytes = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);

/** Arrays the library wiped that held exactly `bytes`, leaving out `exclude`. */
function wipedHolding(bytes: Uint8Array, exclude: Iterable<Uint8Array> = []): Uint8Array[] {
  const skip = new Set(exclude);
  return wipes.log.filter((w) => !skip.has(w.array) && sameBytes(w.before, bytes)).map((w) => w.array);
}

/**
 * What the library hands the provider and gets back, by identity: draws, the
 * private-key copies and outputs of X25519, HKDF's inputs and outputs by shape
 * (X3DH's KM, KDF_RK's salt RK, KDF_CK's input CK), and AEAD keys. `record`
 * clears the wipe log and records only inside `fn`.
 */
function recordProvider() {
  const noble = getPrimitives();
  const seen = {
    draws: [] as Uint8Array[],
    pubFromPriv: [] as Uint8Array[],
    dhPriv: [] as Uint8Array[],
    dhOut: [] as Uint8Array[],
    km: [] as Uint8Array[],
    rootSalt: [] as Uint8Array[],
    chainIn: [] as Uint8Array[],
    hkdfOut: [] as Uint8Array[],
    aeadKey: [] as Uint8Array[],
  };
  let on = false;
  registerCryptoPrimitives({
    name: "recording",
    randomBytes: (n) => {
      const out = noble.randomBytes(n);
      if (on) seen.draws.push(out);
      return out;
    },
    x25519GetPublicKey: (priv) => {
      if (on) seen.pubFromPriv.push(priv);
      return noble.x25519GetPublicKey(priv);
    },
    x25519SharedSecret: (priv, pub) => {
      const out = noble.x25519SharedSecret(priv, pub);
      if (on) {
        seen.dhPriv.push(priv);
        seen.dhOut.push(out);
      }
      return out;
    },
    hkdfSha256: (ikm, salt, info, length) => {
      const out = noble.hkdfSha256(ikm, salt, info, length);
      if (on) {
        seen.hkdfOut.push(out);
        if (length === 32) seen.km.push(ikm); // X3DH: F || DH1 || ... -> SK
        else if (salt.length === 32) seen.rootSalt.push(salt); // KDF_RK: salt = RK
        else seen.chainIn.push(ikm); // KDF_CK: ikm = CK
      }
      return out;
    },
    xchacha20poly1305Encrypt: (key, nonce, pt, aad) => {
      if (on) seen.aeadKey.push(key);
      return noble.xchacha20poly1305Encrypt(key, nonce, pt, aad);
    },
    xchacha20poly1305Decrypt: (key, nonce, ct, aad) => {
      if (on) seen.aeadKey.push(key);
      return noble.xchacha20poly1305Decrypt(key, nonce, ct, aad);
    },
  });
  return {
    seen,
    record<T>(fn: () => T): T {
      wipes.log.length = 0;
      on = true;
      try {
        return fn();
      } finally {
        on = false;
      }
    },
  };
}

/** Encrypts and returns only what goes on the wire. */
function send(state: RatchetState, text: string): { header: ReturnType<typeof ratchetEncrypt>["header"]; ciphertext_b64: string } {
  const { header, ciphertext_b64 } = ratchetEncrypt({ state, plaintext: utf8(text) });
  return { header, ciphertext_b64 };
}

/** Every array a ratchet state holds, by reference. */
function arraysOf(s: RatchetState): Uint8Array[] {
  return [s.ad, s.rk32, s.ck_s32, s.ck_r32, s.dh_self.priv32, s.dh_self.pub32, s.dh_remote_pub32, ...s.skipped.values()].filter(
    (a): a is Uint8Array => a !== undefined
  );
}

function expectAllZero(arrays: Uint8Array[]): void {
  expect(arrays.length).toBeGreaterThan(0);
  for (const a of arrays) expect(isZero(a)).toBe(true);
}

/** Records the arrays randomBytes hands out (the library uses them as keys in place). */
function recordDraws(): { draws: Uint8Array[]; on(): void; off(): void } {
  const noble = getPrimitives();
  const draws: Uint8Array[] = [];
  let recording = false;
  registerCryptoPrimitives({
    name: "recording",
    randomBytes: (n) => {
      const out = noble.randomBytes(n);
      if (recording) draws.push(out);
      return out;
    },
  });
  return { draws, on: () => (recording = true), off: () => (recording = false) };
}

describe("wipe", () => {
  it("zeroes every array it is given and skips absent ones", () => {
    const a = randomBytes(32);
    const b = randomBytes(7);
    wipe(a, undefined, b, null);
    expect(isZero(a) && isZero(b)).toBe(true);
  });

  it("KDF outputs are copies, not views of the wiped HKDF output", () => {
    const rk = kdfRootAndChainKey(randomBytes(32), randomBytes(32));
    const ck = kdfChainKey(randomBytes(32));
    for (const k of [rk.rk32, rk.ck32, ck.ck32, ck.mk32]) expect(isZero(k)).toBe(false);
  });
});

describe("what the library wipes", () => {
  it.each([false, true])(
    "the initiator bootstrap (one-time prekey: %s) wipes EK, every DH output, KM, SK, each HKDF output and its key copies",
    (withOpk) => {
      const bob = X3DHPrekeyManagerV2.create({ recipient_device_id: BOB_DEVICE });
      const bundle = bob.getPrekeyBundle();
      if (withOpk) {
        const [opk] = bob.mintOneTimePrekeys(1, 7);
        bundle.opk_id = opk!.opk_id;
        bundle.opk_pub_b64 = bytesToBase64(opk!.pub32);
      }
      const alice = X3DHPrekeyManagerV2.create({ recipient_device_id: ALICE_DEVICE });
      const rec = recordProvider();
      const { ratchet_state } = rec.record(() =>
        x3dhInitiatorBootstrapV2({
          sender_device_id: ALICE_DEVICE,
          recipient_bundle: bundle,
          expected_recipient_device_id: BOB_DEVICE,
          initiator_ik_priv32: alice.ik.priv32,
          initiator_ik_sig_pub32: alice.ik_sig.pub32,
          trust: new IdentityRegistry(),
        })
      );
      const { seen } = rec;
      const [ek, dhs] = seen.draws;
      // DH1, DH2, DH3 [, DH4], then RatchetInitAlice's DH(DHs, SPK_B).
      expect(seen.dhOut).toHaveLength(withOpk ? 5 : 4);
      expect(seen.km.map((k) => k.length)).toEqual([withOpk ? 160 : 128]);
      expectAllZero([ek!, ...seen.dhOut, ...seen.km, ...seen.hkdfOut, ...seen.rootSalt, ...seen.dhPriv]);
      // The copy of IK_A made to compute its public key; EK; then the DHs, which stays.
      expectAllZero(seen.pubFromPriv.filter((k) => k !== dhs));
      expect(dhs).toBe(ratchet_state.dh_self.priv32);
      expect(isZero(dhs!)).toBe(false);
      expect(alice.ik.priv32.some((b) => b !== 0)).toBe(true);
    }
  );

  it("the responder bootstrap wipes every DH output, KM, SK and its copies of the prekeys", () => {
    const pair = sessionPair({ opkId: 5 });
    const keys = pair.bobKeys;
    const copies: Uint8Array[] = [];
    const getSpk = keys.getSignedPrekey.bind(keys);
    vi.spyOn(keys, "getSignedPrekey").mockImplementation((id) => {
      const rec = getSpk(id);
      copies.push(rec.priv32);
      return rec;
    });
    const getOpk = keys.getOneTimePrekeyPriv32.bind(keys);
    vi.spyOn(keys, "getOneTimePrekeyPriv32").mockImplementation((id) => {
      const priv = getOpk(id);
      copies.push(priv);
      return priv;
    });
    const rec = recordProvider();
    const { ratchet_state } = rec.record(() =>
      x3dhResponderBootstrapV2({
        session_init: pair.session_init,
        prekeys: keys,
        recipient_device_id: BOB_DEVICE,
        sender_device_id: ALICE_DEVICE,
      })
    );
    const { seen } = rec;
    expect(copies).toHaveLength(2);
    expect(seen.dhOut).toHaveLength(4);
    expect(seen.km.map((k) => k.length)).toEqual([160]);
    expect(seen.draws).toHaveLength(0);
    expectAllZero([...copies, ...seen.dhOut, ...seen.km, ...seen.hkdfOut, ...seen.dhPriv, ...seen.pubFromPriv]);
    expect(isZero(ratchet_state.rk32)).toBe(false);
    expect(isZero(ratchet_state.dh_self.priv32)).toBe(false);
  });

  it("encrypt wipes the message key and the KDF output; the caller's chain key stays", () => {
    const { alice } = sessionPair();
    const oldCk = alice.ck_s32!;
    const rec = recordProvider();
    rec.record(() => send(alice, "x"));
    expectAllZero([...rec.seen.aeadKey, ...rec.seen.hkdfOut]);
    expect(rec.seen.chainIn).toEqual([oldCk]);
    expect(isZero(oldCk)).toBe(false);
  });

  it("a decrypt with a DH step wipes both DH outputs, the replaced root and chain keys, the old DHs and the message key", () => {
    const { alice, bob } = establishedPair();
    const r0 = send(bob, "r0");
    ratchetDecrypt({ state: alice, ...r0 });
    const a0 = send(alice, "a0");
    expect(a0.header.dr.pn).toBe(bob.nr); // nothing to skip on the old chain
    const old = {
      ck_r: bob.ck_r32!.slice(),
      ck_s: bob.ck_s32!.slice(),
      priv: bob.dh_self.priv32.slice(),
    };
    const rec = recordProvider();
    rec.record(() => ratchetDecrypt({ state: bob, ...a0 }));
    const { seen } = rec;
    expect(seen.dhOut).toHaveLength(2); // DH(DHs, DHr) before and after the new DHs
    expect(seen.rootSalt).toHaveLength(2); // the copy's RK, then the RK between the two steps
    expect(seen.chainIn).toHaveLength(1); // the new CKr, stepped for the message key
    expect(seen.aeadKey).toHaveLength(1);
    expectAllZero([...seen.dhOut, ...seen.rootSalt, ...seen.chainIn, ...seen.aeadKey, ...seen.hkdfOut, ...seen.dhPriv]);
    // The working copy's old CKr, CKs and DHs private key, found by what they held
    // (the X25519 wrapper's own scalar copies are left out).
    expect(wipedHolding(old.ck_r)).not.toHaveLength(0);
    expect(wipedHolding(old.ck_s)).not.toHaveLength(0);
    expect(wipedHolding(old.priv, seen.dhPriv)).not.toHaveLength(0);
    // The new DHs stays.
    expect(seen.draws).toEqual([bob.dh_self.priv32]);
    for (const k of [bob.rk32, bob.ck_r32!, bob.ck_s32!, bob.dh_self.priv32]) expect(isZero(k)).toBe(false);
  });

  it("the old chain's skip (pn) wipes each chain key it replaces and keeps the stored message keys", () => {
    const { alice, bob } = establishedPair();
    send(alice, "a1");
    send(alice, "a2");
    const r0 = send(bob, "r0");
    ratchetDecrypt({ state: alice, ...r0 });
    const a3 = send(alice, "a3");
    const rec = recordProvider();
    rec.record(() => ratchetDecrypt({ state: bob, ...a3 }));
    // Two skips on the old chain, then the new CKr's step.
    expect(rec.seen.chainIn).toHaveLength(3);
    expectAllZero(rec.seen.chainIn);
    expect(bob.skipped.size).toBe(2);
    for (const mk of bob.skipped.values()) expect(isZero(mk)).toBe(false);
  });

  it("a decrypt from the skipped cache wipes its copy of the key", () => {
    const { alice, bob } = sessionPair();
    const m0 = send(alice, "0");
    const m1 = send(alice, "1");
    ratchetDecrypt({ state: bob, ...m1 });
    const [stored] = bob.skipped.values();
    const rec = recordProvider();
    rec.record(() => ratchetDecrypt({ state: bob, ...m0 }));
    expect(rec.seen.aeadKey).toHaveLength(1);
    expectAllZero(rec.seen.aeadKey);
    expect(rec.seen.aeadKey[0]).not.toBe(stored);
    expect(isZero(stored!)).toBe(false);
  });

  it("a key evicted at MAX_SKIPPED_KEYS is wiped in the working copy, not in the caller's map", () => {
    expect(MAX_SKIPPED_KEYS).toBe(2 * MAX_SKIP_DERIVE); // the fill below relies on it
    const { alice, bob } = sessionPair();
    const sent = Array.from({ length: 2 * MAX_SKIP_DERIVE + 4 }, (_, n) =>
      send(alice, `m${n}`)
    );
    ratchetDecrypt({ state: bob, ...sent[MAX_SKIP_DERIVE]! });
    ratchetDecrypt({ state: bob, ...sent[2 * MAX_SKIP_DERIVE + 1]! });
    expect(bob.skipped.size).toBe(MAX_SKIPPED_KEYS);
    const [oldestId, oldest] = bob.skipped.entries().next().value!;
    const held = oldest.slice();
    const rec = recordProvider();
    rec.record(() => ratchetDecrypt({ state: bob, ...sent[2 * MAX_SKIP_DERIVE + 3]! }));
    expect(bob.skipped.has(oldestId)).toBe(false);
    expect(wipedHolding(held)).not.toHaveLength(0);
    expect(oldest).toEqual(held);
  });

  it("a failed decrypt on the current chain wipes every secret of its working copy", () => {
    const { alice, bob } = establishedPair();
    send(alice, "a1");
    const a2 = send(alice, "a2");
    ratchetDecrypt({ state: bob, ...a2 }); // stores a1's key
    const a3 = send(alice, "a3");
    const tampered = Buffer.from(a3.ciphertext_b64, "base64");
    tampered[0]! ^= 1;
    const before = snapshot(bob);
    const held = {
      rk: bob.rk32.slice(),
      ck_s: bob.ck_s32!.slice(),
      priv: bob.dh_self.priv32.slice(),
      skipped: [...bob.skipped.values()].map((k) => k.slice()),
      // The copy's CKr after the message key's step, which only the failure wipes.
      ck_r_next: kdfChainKey(bob.ck_r32!).ck32,
    };
    const rec = recordProvider();
    expect(() =>
      rec.record(() => ratchetDecrypt({ state: bob, header: a3.header, ciphertext_b64: tampered.toString("base64") }))
    ).toThrow(DecryptFailedError);
    expectAllZero([...rec.seen.aeadKey, ...rec.seen.chainIn]);
    for (const bytes of [held.rk, held.ck_s, held.priv, held.ck_r_next, ...held.skipped]) {
      expect(wipedHolding(bytes)).not.toHaveLength(0);
    }
    expect(snapshot(bob)).toBe(before);
  });

  it("the initiator's ephemeral private key is wiped after X3DH; the sending key stays", () => {
    const bob = X3DHPrekeyManagerV2.create({ recipient_device_id: BOB_DEVICE });
    const alice = X3DHPrekeyManagerV2.create({ recipient_device_id: ALICE_DEVICE });
    const rec = recordDraws();
    rec.on();
    const { ratchet_state } = x3dhInitiatorBootstrapV2({
      sender_device_id: ALICE_DEVICE,
      recipient_bundle: bob.getPrekeyBundle(),
      expected_recipient_device_id: BOB_DEVICE,
      initiator_ik_priv32: alice.ik.priv32,
      initiator_ik_sig_pub32: alice.ik_sig.pub32,
      trust: new IdentityRegistry(),
    });
    rec.off();
    const [ek, dhs] = rec.draws;
    expect(isZero(ek!)).toBe(true);
    expect(dhs).toBe(ratchet_state.dh_self.priv32);
    expect(isZero(dhs!)).toBe(false);
  });

  it("a failed decrypt wipes its working copy, the trial DH key included, and leaves the caller's state byte-identical", () => {
    const { alice, bob } = sessionPair();
    const m = send(alice, "x");
    const tampered = Buffer.from(m.ciphertext_b64, "base64");
    tampered[0]! ^= 1;
    const before = snapshot(bob);
    const rec = recordDraws();
    rec.on();
    expect(() => ratchetDecrypt({ state: bob, header: m.header, ciphertext_b64: tampered.toString("base64") })).toThrow(
      DecryptFailedError
    );
    rec.off();
    expect(rec.draws).toHaveLength(1);
    expect(isZero(rec.draws[0]!)).toBe(true);
    expect(snapshot(bob)).toBe(before);
    expect(ratchetDecrypt({ state: bob, header: m.header, ciphertext_b64: m.ciphertext_b64 }).plaintext).toEqual(utf8("x"));
  });

  it("a successful decrypt keeps every key the state still needs", () => {
    const { alice, bob } = sessionPair();
    const m0 = send(alice, "0");
    const m1 = send(alice, "1");
    ratchetDecrypt({ state: bob, header: m1.header, ciphertext_b64: m1.ciphertext_b64 });
    for (const k of [bob.rk32, bob.ck_r32!, bob.ck_s32!, bob.dh_self.priv32, ...bob.skipped.values()]) {
      expect(isZero(k)).toBe(false);
    }
    expect(ratchetDecrypt({ state: bob, header: m0.header, ciphertext_b64: m0.ciphertext_b64 }).plaintext).toEqual(utf8("0"));
  });
});

describe("what the library never wipes: arrays from a caller or a store", () => {
  it("a successful encrypt and a successful decrypt leave every array of the caller's previous state unchanged", () => {
    const { alice, bob } = establishedPair();
    const a1 = send(alice, "a1");
    const a2 = send(alice, "a2");
    const steps: Array<[string, RatchetState, () => unknown]> = [
      ["encrypt", bob, () => send(bob, "r0")],
      ["decrypt on the current chain, storing a skipped key", bob, () => ratchetDecrypt({ state: bob, ...a2 })],
      ["decrypt from the skipped cache", bob, () => ratchetDecrypt({ state: bob, ...a1 })],
    ];
    for (const [label, state, step] of steps) {
      const refs = arraysOf(state);
      const copies = refs.map((a) => a.slice());
      step();
      refs.forEach((a, i) => expect(a, label).toEqual(copies[i]));
    }
    // A DH step with an old-chain skip, on Alice's side and then on Bob's.
    const r1 = send(bob, "r1");
    const aliceRefs = arraysOf(alice);
    const aliceCopies = aliceRefs.map((a) => a.slice());
    ratchetDecrypt({ state: alice, ...r1 });
    aliceRefs.forEach((a, i) => expect(a, "decrypt with a DH step").toEqual(aliceCopies[i]));
    send(alice, "a3");
    const a4 = send(alice, "a4");
    const bobRefs = arraysOf(bob);
    const bobCopies = bobRefs.map((a) => a.slice());
    ratchetDecrypt({ state: bob, ...a4 });
    bobRefs.forEach((a, i) => expect(a, "decrypt with a DH step and a skip").toEqual(bobCopies[i]));
  });

  it("X3DH and ratchet inputs", () => {
    const pair = sessionPair({ opkId: 5 });
    const bobKeys = pair.bobKeys;
    const spk = bobKeys.getCurrentSignedPrekey();
    const opkPriv = bobKeys.getOneTimePrekeyPriv32(5);
    const inputs = {
      ik: new Uint8Array(bobKeys.ik.priv32),
      spk: new Uint8Array(spk.priv32),
      opk: new Uint8Array(opkPriv),
    };
    const { sk32, ad } = x3dhResponderV2({
      session_init: pair.session_init,
      sender_device_id: ALICE_DEVICE,
      recipient_device_id: BOB_DEVICE,
      recipient_ik_priv32: bobKeys.ik.priv32,
      recipient_ik_sig_pub32: bobKeys.ik_sig.pub32,
      recipient_spk_priv32: spk.priv32,
      recipient_opk_priv32: opkPriv,
    });
    expect(bobKeys.ik.priv32).toEqual(inputs.ik);
    expect(spk.priv32).toEqual(inputs.spk);
    expect(opkPriv).toEqual(inputs.opk);
    expect(isZero(sk32)).toBe(false);

    const skCopy = new Uint8Array(sk32);
    ratchetInitResponderV2({ sk32, ad, selfSpk: spk });
    expect(sk32).toEqual(skCopy);
    expect(spk.priv32).toEqual(inputs.spk);
  });

  it("the prekey manager's keys survive a responder bootstrap (alias regression)", () => {
    const pair = sessionPair({ opkId: 5 });
    const before = JSON.stringify(pair.bobKeys.exportState());
    const { ratchet_state } = x3dhResponderBootstrapV2({
      session_init: pair.session_init,
      prekeys: pair.bobKeys,
      recipient_device_id: BOB_DEVICE,
      sender_device_id: ALICE_DEVICE,
    });
    expect(JSON.stringify(pair.bobKeys.exportState())).toBe(before);
    expect(isZero(ratchet_state.dh_self.priv32)).toBe(false);
    expect(isZero(ratchet_state.rk32)).toBe(false);
  });

  it("caller keys and plaintext in seals", () => {
    const key32 = randomBytes(32);
    const keyCopy = new Uint8Array(key32);
    const plaintext = utf8("note");
    const aad = buildSelfSealAadV2(ALICE_DEVICE);
    const sealed = sealLocalV2({ key32, aad, plaintext });
    openLocalV2({ key32, aad, ...sealed });
    expect(key32).toEqual(keyCopy);
    expect(plaintext).toEqual(utf8("note"));
  });
});

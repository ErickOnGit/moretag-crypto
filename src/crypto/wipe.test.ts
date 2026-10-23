import { describe, it, expect, afterEach } from "vitest";
import { wipe } from "./wipe.js";
import { getPrimitives, registerCryptoPrimitives, resetCryptoPrimitives } from "./primitives.js";
import { kdfChainKey, kdfRootAndChainKey } from "./kdf.js";
import { x3dhResponderV2 } from "./x3dh.js";
import { sealLocalV2, openLocalV2, buildSelfSealAadV2 } from "./seal.js";
import { randomBytes } from "@noble/ciphers/utils.js";
import { ratchetDecrypt, ratchetEncrypt, ratchetInitResponderV2 } from "../ratchet/ratchet.js";
import { serializeRatchetStateV2 } from "../ratchet/serialization.js";
import { x3dhInitiatorBootstrapV2, x3dhResponderBootstrapV2 } from "../x3dh/session.js";
import { X3DHPrekeyManagerV2 } from "../x3dh/prekey-manager.js";
import { IdentityRegistry } from "../identity/trust.js";
import { DecryptFailedError } from "../errors.js";
import { ALICE_DEVICE, BOB_DEVICE, sessionPair, utf8 } from "../test-fixtures.js";

afterEach(() => resetCryptoPrimitives());

const isZero = (b: Uint8Array) => b.every((x) => x === 0);
const snapshot = (s: Parameters<typeof serializeRatchetStateV2>[0]) => JSON.stringify(serializeRatchetStateV2(s));

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
    const m = ratchetEncrypt({ state: alice, plaintext: utf8("x") });
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
    const m0 = ratchetEncrypt({ state: alice, plaintext: utf8("0") });
    const m1 = ratchetEncrypt({ state: alice, plaintext: utf8("1") });
    ratchetDecrypt({ state: bob, header: m1.header, ciphertext_b64: m1.ciphertext_b64 });
    for (const k of [bob.rk32, bob.ck_r32!, bob.ck_s32!, bob.dh_self.priv32, ...bob.skipped.values()]) {
      expect(isZero(k)).toBe(false);
    }
    expect(ratchetDecrypt({ state: bob, header: m0.header, ciphertext_b64: m0.ciphertext_b64 }).plaintext).toEqual(utf8("0"));
  });
});

describe("what the library never wipes: arrays from a caller or a store", () => {
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

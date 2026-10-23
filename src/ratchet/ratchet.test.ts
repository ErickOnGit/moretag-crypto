import { describe, it, expect } from "vitest";
import {
  ratchetInitInitiatorV2,
  ratchetInitResponderV2,
  ratchetEncrypt,
  ratchetDecrypt,
  type RatchetState,
} from "./ratchet.js";
import { serializeRatchetStateV2 } from "./serialization.js";
import {
  DecryptFailedError,
  DeviceMismatchError,
  InvalidWireError,
  NoSendingChainError,
  ReplayDetectedError,
  SkipLimitError,
} from "../errors.js";
import { generateEd25519Keypair } from "../crypto/ed25519.js";
import { generateX25519Keypair, x25519SharedSecret } from "../crypto/x25519.js";
import { kdfRootAndChainKey } from "../crypto/kdf.js";
import { buildAssociatedDataV2 } from "../crypto/ad.js";
import { randomBytes } from "@noble/ciphers/utils.js";
import {
  MAX_CIPHERTEXT_BYTES,
  MAX_PLAINTEXT_BYTES,
  MAX_SKIP_DERIVE,
  MAX_SKIPPED_KEYS,
} from "../crypto/limits.js";
import { bytesToBase64 } from "../encoding/base64.js";
import { x3dhResponderBootstrapV2 } from "../x3dh/session.js";
import {
  ALICE_DEVICE,
  BOB_DEVICE,
  CAROL_DEVICE,
  establishedPair,
  sessionPair,
  utf8,
} from "../test-fixtures.js";
import type { HeaderProtoV2 } from "../wire/header.js";

const text = (b: Uint8Array) => new TextDecoder().decode(b);
const snapshot = (state: RatchetState) => JSON.stringify(serializeRatchetStateV2(state));

function send(state: RatchetState, message: string, grp?: { gid: string; epoch: number }) {
  const { header, ciphertext_b64 } = ratchetEncrypt({
    state,
    plaintext: utf8(message),
    ...(grp ? { grp } : {}),
  });
  return { header, ciphertext_b64 };
}

function thrownBy(fn: () => unknown): unknown {
  try {
    fn();
  } catch (err) {
    return err;
  }
  throw new Error("expected a throw");
}

function randomAd(devA = ALICE_DEVICE, devB = BOB_DEVICE): Uint8Array {
  return buildAssociatedDataV2({
    initiator_ik_pub32: generateX25519Keypair().pub32,
    responder_ik_pub32: generateX25519Keypair().pub32,
    initiator_ik_sig_pub32: generateEd25519Keypair().pub32,
    responder_ik_sig_pub32: generateEd25519Keypair().pub32,
    initiator_device_id: devA,
    responder_device_id: devB,
  });
}

describe("initialization (DR §3.3)", () => {
  it("the initiator draws DHs, sets DHr to the signed prekey and derives RK and CKs from SK", () => {
    const sk32 = randomBytes(32);
    const ad = randomAd();
    const spk = generateX25519Keypair();
    const alice = ratchetInitInitiatorV2({ sk32, ad, remoteSpkPub32: spk.pub32 });

    const expected = kdfRootAndChainKey(sk32, x25519SharedSecret(alice.dh_self.priv32, spk.pub32));
    expect(alice.role).toBe("initiator");
    expect(alice.rk32).toEqual(expected.rk32);
    expect(alice.ck_s32).toEqual(expected.ck32);
    expect(alice.ck_r32).toBeUndefined();
    expect(alice.dh_remote_pub32).toEqual(spk.pub32);
    expect([alice.ns, alice.nr, alice.pn]).toEqual([0, 0, 0]);
    expect(alice.ad).toEqual(ad);
  });

  it("the responder keeps the signed prekey pair as DHs, RK = SK, no DHr and no chains", () => {
    const sk32 = randomBytes(32);
    const ad = randomAd();
    const spk = generateX25519Keypair();
    const bob = ratchetInitResponderV2({ sk32, ad, selfSpk: spk });

    expect(bob.role).toBe("responder");
    expect(bob.rk32).toEqual(sk32);
    expect(bob.dh_self).toEqual(spk);
    expect(bob.dh_remote_pub32).toBeUndefined();
    expect(bob.ck_s32).toBeUndefined();
    expect(bob.ck_r32).toBeUndefined();
  });

  it("every input is copied", () => {
    const sk32 = randomBytes(32);
    const ad = randomAd();
    const spk = generateX25519Keypair();
    const bob = ratchetInitResponderV2({ sk32, ad, selfSpk: spk });
    const alice = ratchetInitInitiatorV2({ sk32, ad, remoteSpkPub32: spk.pub32 });
    for (const input of [sk32, ad, spk.priv32, spk.pub32]) input.fill(0);
    expect(bob.rk32.some((b) => b !== 0)).toBe(true);
    expect(bob.ad.some((b) => b !== 0)).toBe(true);
    expect(bob.dh_self.priv32.some((b) => b !== 0)).toBe(true);
    expect(alice.ad.some((b) => b !== 0)).toBe(true);
    expect(alice.dh_remote_pub32!.some((b) => b !== 0)).toBe(true);
  });

  it("refuses a malformed associated data", () => {
    const spk = generateX25519Keypair();
    expect(() =>
      ratchetInitInitiatorV2({ sk32: randomBytes(32), ad: new Uint8Array(164), remoteSpkPub32: spk.pub32 })
    ).toThrow(TypeError);
  });
});

describe("Double Ratchet", () => {
  it("round-trips in both directions, with a DH step each way, under one AD", () => {
    const { alice, bob } = sessionPair();
    expect(alice.ad).toEqual(bob.ad);

    const m0 = send(alice, "hello bob");
    expect(text(ratchetDecrypt({ state: bob, ...m0 }).plaintext)).toBe("hello bob");
    const r0 = send(bob, "hello alice");
    expect(r0.header.sender_device_id).toBe(BOB_DEVICE);
    expect(r0.header.recipient_device_id).toBe(ALICE_DEVICE);
    expect(text(ratchetDecrypt({ state: alice, ...r0 }).plaintext)).toBe("hello alice");
    const m1 = send(alice, "again");
    expect(m1.header.dr.dh_pub_b64).not.toBe(m0.header.dr.dh_pub_b64);
    expect(text(ratchetDecrypt({ state: bob, ...m1 }).plaintext)).toBe("again");
    expect(alice.ad).toEqual(bob.ad);
  });

  it("writes the header ids from AD by role", () => {
    const { alice } = sessionPair();
    const m0 = send(alice, "x");
    expect(m0.header.sender_device_id).toBe(ALICE_DEVICE);
    expect(m0.header.recipient_device_id).toBe(BOB_DEVICE);
    expect(m0.header.v).toBe(2);
    expect(m0.header).not.toHaveProperty("grp");
  });

  it("handles out-of-order receive using skipped message keys", () => {
    const { alice, bob } = sessionPair();
    const m1 = send(alice, "m1");
    const m2 = send(alice, "m2");
    expect(text(ratchetDecrypt({ state: bob, ...m2 }).plaintext)).toBe("m2");
    expect(text(ratchetDecrypt({ state: bob, ...m1 }).plaintext)).toBe("m1");
  });

  it("a state whose AD differs cannot read the message", () => {
    const { alice, bob } = sessionPair();
    const m0 = send(alice, "x");
    const other = { ...bob, ad: randomAd() };
    expect(thrownBy(() => ratchetDecrypt({ state: other, ...m0 }))).toBeInstanceOf(DecryptFailedError);
  });

  it("a header id differing from AD is device_mismatch before the AEAD, state unchanged", () => {
    const { alice, bob } = sessionPair();
    const m0 = send(alice, "x");
    const before = snapshot(bob);
    for (const header of [
      { ...m0.header, sender_device_id: CAROL_DEVICE },
      { ...m0.header, recipient_device_id: CAROL_DEVICE },
      { ...m0.header, sender_device_id: BOB_DEVICE },
    ]) {
      const err = thrownBy(() => ratchetDecrypt({ state: bob, header, ciphertext_b64: m0.ciphertext_b64 }));
      expect(err).toBeInstanceOf(DeviceMismatchError);
      expect((err as DeviceMismatchError).code).toBe("device_mismatch");
    }
    expect(snapshot(bob)).toBe(before);
    expect(text(ratchetDecrypt({ state: bob, ...m0 }).plaintext)).toBe("x");
  });

  it("encrypt without a sending chain throws no_sending_chain and changes nothing", () => {
    const { bob } = sessionPair();
    const before = snapshot(bob);
    const err = thrownBy(() => ratchetEncrypt({ state: bob, plaintext: utf8("x") }));
    expect(err).toBeInstanceOf(NoSendingChainError);
    expect((err as NoSendingChainError).code).toBe("no_sending_chain");
    expect(snapshot(bob)).toBe(before);
  });

  it("the group slot round-trips authenticated, and pairwise messages return null", () => {
    const { alice, bob } = sessionPair();
    const grp = { gid: CAROL_DEVICE, epoch: 2 ** 40 };
    const m0 = send(alice, "group", grp);
    expect(m0.header.grp).toEqual(grp);
    expect(ratchetDecrypt({ state: bob, ...m0 }).grp).toEqual(grp);
    const m1 = send(alice, "pairwise");
    expect(ratchetDecrypt({ state: bob, ...m1 }).grp).toBeNull();
  });

  it("a changed or stripped group slot fails authentication", () => {
    const { alice, bob } = sessionPair();
    const m0 = send(alice, "group", { gid: CAROL_DEVICE, epoch: 3 });
    const before = snapshot(bob);
    const changed = { ...m0.header, grp: { gid: CAROL_DEVICE, epoch: 4 } };
    const { grp: _dropped, ...stripped } = m0.header;
    for (const header of [changed, stripped as HeaderProtoV2]) {
      expect(thrownBy(() => ratchetDecrypt({ state: bob, header, ciphertext_b64: m0.ciphertext_b64 }))).toBeInstanceOf(
        DecryptFailedError
      );
    }
    expect(snapshot(bob)).toBe(before);
  });

  it("a malformed group slot is refused on both sides", () => {
    const { alice, bob } = sessionPair();
    const m0 = send(alice, "x");
    const bad = [
      { gid: CAROL_DEVICE.toUpperCase(), epoch: 1 },
      { gid: CAROL_DEVICE, epoch: -1 },
      { gid: CAROL_DEVICE, epoch: 1.5 },
      { gid: CAROL_DEVICE },
      "group",
    ];
    for (const grp of bad) {
      const header = { ...m0.header, grp } as unknown as HeaderProtoV2;
      const err = thrownBy(() => ratchetDecrypt({ state: bob, header, ciphertext_b64: m0.ciphertext_b64 }));
      expect((err as InvalidWireError).code).toBe("invalid_grp");
      const encErr = thrownBy(() =>
        ratchetEncrypt({ state: alice, plaintext: utf8("x"), grp: grp as never })
      );
      expect((encErr as InvalidWireError).code).toBe("invalid_grp");
    }
  });

  it("X3DH §4.3: two responder bootstraps from one setup reply with different keys", () => {
    const { alice, bobKeys, session_init } = sessionPair();
    const m0 = send(alice, "x");
    const replies = [0, 1].map(() => {
      const { ratchet_state } = x3dhResponderBootstrapV2({
        session_init,
        prekeys: bobKeys,
        recipient_device_id: BOB_DEVICE,
        sender_device_id: ALICE_DEVICE,
      });
      ratchetDecrypt({ state: ratchet_state, ...m0 });
      return send(ratchet_state, "same reply");
    });
    expect(replies[0]!.header.dr.dh_pub_b64).not.toBe(replies[1]!.header.dr.dh_pub_b64);
    expect(replies[0]!.ciphertext_b64).not.toBe(replies[1]!.ciphertext_b64);
  });

  it("rejects plaintext exceeding limit", () => {
    const { alice } = sessionPair();
    const before = snapshot(alice);
    expect(() =>
      ratchetEncrypt({ state: alice, plaintext: new Uint8Array(MAX_PLAINTEXT_BYTES + 1) })
    ).toThrow(/Plaintext too large/);
    expect(snapshot(alice)).toBe(before);
  });

  it("a gap over MAX_SKIP is skip_limit_exceeded, on the current chain and on pn before a DH step, state unchanged", () => {
    const { alice, bob } = establishedPair();
    const m = send(alice, "ok");
    const nGap: HeaderProtoV2 = { ...m.header, dr: { ...m.header.dr, n: bob.nr + MAX_SKIP_DERIVE + 1 } };
    const reply = send(bob, "reply");
    const bobAfterReply = snapshot(bob);
    // Alice's next chain claims a previous chain one past the limit.
    const pnGap: HeaderProtoV2 = {
      ...m.header,
      dr: { dh_pub_b64: bytesToBase64(generateX25519Keypair().pub32), pn: bob.nr + MAX_SKIP_DERIVE + 1, n: 0 },
    };
    for (const header of [nGap, pnGap]) {
      const err = thrownBy(() => ratchetDecrypt({ state: bob, header, ciphertext_b64: m.ciphertext_b64 }));
      expect(err).toBeInstanceOf(SkipLimitError);
      expect((err as SkipLimitError).code).toBe("skip_limit_exceeded");
    }
    expect(snapshot(bob)).toBe(bobAfterReply);
    // Exactly MAX_SKIP is allowed: the gap is derived, then the AEAD refuses the forgery.
    const atLimit: HeaderProtoV2 = { ...m.header, dr: { ...m.header.dr, n: bob.nr + MAX_SKIP_DERIVE } };
    expect(thrownBy(() => ratchetDecrypt({ state: bob, header: atLimit, ciphertext_b64: m.ciphertext_b64 }))).toBeInstanceOf(
      DecryptFailedError
    );
    expect(text(ratchetDecrypt({ state: bob, ...m }).plaintext)).toBe("ok");
    expect(text(ratchetDecrypt({ state: alice, ...reply }).plaintext)).toBe("reply");
  });

  it("a header naming the responder's signed prekey before the first reply is decrypt_failed, state unchanged", () => {
    // The initiator keeps DHr = SPK_B, which is public in the bundle, and has no
    // receiving chain until the first reply. A header on that key reaches no chain.
    const { alice, bob, bobKeys } = sessionPair();
    const m0 = send(alice, "x");
    const forged: HeaderProtoV2 = {
      v: 2,
      alg: "xchacha20poly1305",
      nonce_b64: m0.header.nonce_b64,
      sender_device_id: BOB_DEVICE,
      recipient_device_id: ALICE_DEVICE,
      dr: { dh_pub_b64: bytesToBase64(bobKeys.getCurrentSignedPrekey().pub32), pn: 0, n: 0 },
    };
    const before = snapshot(alice);
    for (const n of [0, 3]) {
      const err = thrownBy(() =>
        ratchetDecrypt({ state: alice, header: { ...forged, dr: { ...forged.dr, n } }, ciphertext_b64: m0.ciphertext_b64 })
      );
      expect(err).toBeInstanceOf(DecryptFailedError);
      expect((err as DecryptFailedError).code).toBe("decrypt_failed");
    }
    expect(snapshot(alice)).toBe(before);
    ratchetDecrypt({ state: bob, ...m0 });
    const reply = send(bob, "reply");
    expect(text(ratchetDecrypt({ state: alice, ...reply }).plaintext)).toBe("reply");
  });

  it("a ciphertext that is not strict base64, or over the size limit, is invalid_header, state unchanged", () => {
    const { alice, bob } = sessionPair();
    const m = send(alice, "x");
    const before = snapshot(bob);
    const oversize = bytesToBase64(new Uint8Array(MAX_CIPHERTEXT_BYTES + 1));
    for (const ciphertext_b64 of ["", "not base64!", "AB==", m.ciphertext_b64.slice(1), 42, null, oversize]) {
      const err = thrownBy(() => ratchetDecrypt({ state: bob, header: m.header, ciphertext_b64: ciphertext_b64 as string }));
      expect(err).toBeInstanceOf(InvalidWireError);
      expect((err as InvalidWireError).code).toBe("invalid_header");
      expect((err as InvalidWireError).message).toBe("Invalid header: ciphertext_b64");
    }
    expect(snapshot(bob)).toBe(before);
    // Exactly at the limit passes the size check and fails the AEAD.
    const atLimit = bytesToBase64(new Uint8Array(MAX_CIPHERTEXT_BYTES));
    expect(thrownBy(() => ratchetDecrypt({ state: bob, header: m.header, ciphertext_b64: atLimit }))).toBeInstanceOf(
      DecryptFailedError
    );
    expect(text(ratchetDecrypt({ state: bob, ...m }).plaintext)).toBe("x");
  });

  it("rejects non-integer or negative counters in headers", () => {
    const { alice, bob } = sessionPair();
    const m = send(alice, "x");
    for (const dr of [
      { ...m.header.dr, pn: -1 },
      { ...m.header.dr, n: 1.5 },
      { ...m.header.dr, n: 2 ** 53 },
    ]) {
      const err = thrownBy(() =>
        ratchetDecrypt({ state: bob, header: { ...m.header, dr }, ciphertext_b64: m.ciphertext_b64 })
      );
      expect(err).toBeInstanceOf(InvalidWireError);
      expect((err as InvalidWireError).code).toBe("invalid_header");
    }
  });

  it("rejects a v1 header", () => {
    const { alice, bob } = sessionPair();
    const m = send(alice, "x");
    const header = { ...m.header, v: 1 } as unknown as HeaderProtoV2;
    expect((thrownBy(() => ratchetDecrypt({ state: bob, header, ciphertext_b64: m.ciphertext_b64 })) as InvalidWireError).code).toBe(
      "invalid_header"
    );
  });

  it("extra header keys, such as a sidecar, do not change the AAD", () => {
    const { alice, bob, session_init } = sessionPair();
    const m = send(alice, "x");
    const header = { ...m.header, session_init } as HeaderProtoV2;
    expect(text(ratchetDecrypt({ state: bob, header, ciphertext_b64: m.ciphertext_b64 }).plaintext)).toBe("x");
  });

  it("a nonce is random per message", () => {
    const { alice } = sessionPair();
    expect(send(alice, "a").header.nonce_b64).not.toBe(send(alice, "a").header.nonce_b64);
  });
});

describe("replay detection", () => {
  it("an in-order replay throws ReplayDetectedError and leaves the state identical", () => {
    const { alice, bob } = sessionPair();
    const m0 = send(alice, "m0");
    ratchetDecrypt({ state: bob, ...m0 });
    const before = snapshot(bob);

    expect(thrownBy(() => ratchetDecrypt({ state: bob, ...m0 }))).toBeInstanceOf(ReplayDetectedError);
    expect(snapshot(bob)).toBe(before);
  });

  it("a replay of a consumed skipped message throws ReplayDetectedError and leaves the state identical", () => {
    const { alice, bob } = sessionPair();
    const m0 = send(alice, "m0");
    const m1 = send(alice, "m1");
    ratchetDecrypt({ state: bob, ...m1 });
    ratchetDecrypt({ state: bob, ...m0 }); // from the skipped cache
    const before = snapshot(bob);

    expect(thrownBy(() => ratchetDecrypt({ state: bob, ...m0 }))).toBeInstanceOf(ReplayDetectedError);
    expect(snapshot(bob)).toBe(before);
  });

  it("at MAX_SKIPPED_KEYS the oldest skipped key is evicted, not the message refused", () => {
    expect(MAX_SKIPPED_KEYS).toBe(2 * MAX_SKIP_DERIVE); // the fill below relies on it
    const { alice, bob } = establishedPair();
    const sent = Array.from({ length: 3 * MAX_SKIP_DERIVE + 3 }, (_, n) => send(alice, `m${n}`));

    // Two gaps of MAX_SKIP_DERIVE fill the cache.
    ratchetDecrypt({ state: bob, ...sent[MAX_SKIP_DERIVE]! });
    ratchetDecrypt({ state: bob, ...sent[2 * MAX_SKIP_DERIVE + 1]! });
    expect(bob.skipped.size).toBe(MAX_SKIPPED_KEYS);

    // A further gap succeeds, evicting the oldest 1,000.
    const last = sent[3 * MAX_SKIP_DERIVE + 2]!;
    expect(text(ratchetDecrypt({ state: bob, ...last }).plaintext)).toBe(`m${3 * MAX_SKIP_DERIVE + 2}`);
    expect(bob.skipped.size).toBe(MAX_SKIPPED_KEYS);

    // The newest skipped message still decrypts; the oldest, evicted, is a replay.
    const newest = sent[3 * MAX_SKIP_DERIVE + 1]!;
    expect(text(ratchetDecrypt({ state: bob, ...newest }).plaintext)).toBe(`m${3 * MAX_SKIP_DERIVE + 1}`);
    expect(thrownBy(() => ratchetDecrypt({ state: bob, ...sent[0]! }))).toBeInstanceOf(ReplayDetectedError);
  });

  it("a replay from an earlier receiving chain is not ReplayDetectedError", () => {
    const { alice, bob } = sessionPair();
    const m0 = send(alice, "m0");
    ratchetDecrypt({ state: bob, ...m0 });
    const reply = send(bob, "reply");
    ratchetDecrypt({ state: alice, ...reply });
    const m1 = send(alice, "m1"); // new sending chain: Bob's receiving chain moves on
    ratchetDecrypt({ state: bob, ...m1 });
    const before = snapshot(bob);

    const err = thrownBy(() => ratchetDecrypt({ state: bob, ...m0 }));
    expect(err).not.toBeInstanceOf(ReplayDetectedError);
    expect(err).toBeInstanceOf(DecryptFailedError);
    expect(snapshot(bob)).toBe(before);
  });
});

import { describe, it, expect, afterEach } from "vitest";
import { X3DHPrekeyManagerV2 } from "./prekey-manager.js";
import { x3dhInitiatorBootstrapV2, x3dhResponderBootstrapV2 } from "./session.js";
import { IdentityRegistry } from "../identity/trust.js";
import { ratchetDecrypt, ratchetEncrypt } from "../ratchet/ratchet.js";
import { bytesToBase64 } from "../encoding/base64.js";
import { x25519PublicFromPrivate } from "../crypto/x25519.js";
import { getPrimitives, registerCryptoPrimitives, resetCryptoPrimitives } from "../crypto/primitives.js";
import {
  BadSignatureError,
  DeviceMismatchError,
  IdentityMismatchError,
  SelfSessionError,
  UnknownPrekeyError,
} from "../errors.js";
import type { X3DHPrekeyBundleV2 } from "../wire/x3dh.js";
import { ALICE_DEVICE, BOB_DEVICE, CAROL_DEVICE, utf8 } from "../test-fixtures.js";

afterEach(() => resetCryptoPrimitives());

function parties(opts: { opkId?: number } = {}) {
  const alice = X3DHPrekeyManagerV2.create({ recipient_device_id: ALICE_DEVICE });
  const bob = X3DHPrekeyManagerV2.create({ recipient_device_id: BOB_DEVICE });
  const bundle: X3DHPrekeyBundleV2 = bob.getPrekeyBundle();
  if (opts.opkId !== undefined) {
    const [opk] = bob.mintOneTimePrekeys(1, opts.opkId);
    bundle.opk_id = opk!.opk_id;
    bundle.opk_pub_b64 = bytesToBase64(opk!.pub32);
  }
  return { alice, bob, bundle };
}

function initiate(alice: X3DHPrekeyManagerV2, bundle: X3DHPrekeyBundleV2, trust: IdentityRegistry, expected = BOB_DEVICE) {
  return x3dhInitiatorBootstrapV2({
    sender_device_id: ALICE_DEVICE,
    recipient_bundle: bundle,
    expected_recipient_device_id: expected,
    initiator_ik_priv32: alice.ik.priv32,
    initiator_ik_sig_pub32: alice.ik_sig.pub32,
    trust,
  });
}

function respond(bob: X3DHPrekeyManagerV2, session_init: ReturnType<typeof initiate>["session_init"], sender = ALICE_DEVICE) {
  return x3dhResponderBootstrapV2({ session_init, prekeys: bob, recipient_device_id: BOB_DEVICE, sender_device_id: sender });
}

function thrownBy(fn: () => unknown): unknown {
  try {
    fn();
  } catch (err) {
    return err;
  }
  throw new Error("expected a throw");
}

describe("initiator bootstrap", () => {
  it("pins the recipient's two keys on first use and refuses a changed identity", () => {
    const { alice, bundle } = parties();
    const trust = new IdentityRegistry();
    initiate(alice, bundle, trust);
    expect(trust.get(BOB_DEVICE)).toMatchObject({ ik_pub_b64: bundle.ik_pub_b64, ik_sig_pub_b64: bundle.ik_sig_pub_b64 });

    const impostor = X3DHPrekeyManagerV2.create({ recipient_device_id: BOB_DEVICE }).getPrekeyBundle();
    expect(thrownBy(() => initiate(alice, impostor, trust))).toBeInstanceOf(IdentityMismatchError);
    expect(trust.isBlocked(BOB_DEVICE)).toBe(true);
  });

  it("a bad bundle signature is refused before the pin: the registry is unchanged", () => {
    const { alice, bundle } = parties();
    const trust = new IdentityRegistry();
    const forged = { ...bundle, spk_pub_b64: bundle.ik_pub_b64 };
    expect(thrownBy(() => initiate(alice, forged, trust))).toBeInstanceOf(BadSignatureError);
    expect(trust.exportState()).toEqual(new IdentityRegistry().exportState());
  });

  it("a bundle for another device is device_mismatch before the pin: the registry is unchanged", () => {
    const { alice } = parties();
    const carol = X3DHPrekeyManagerV2.create({ recipient_device_id: CAROL_DEVICE });
    const trust = new IdentityRegistry();
    expect(thrownBy(() => initiate(alice, carol.getPrekeyBundle(), trust))).toBeInstanceOf(DeviceMismatchError);
    expect(trust.get(CAROL_DEVICE)).toBeNull();
  });

  it("refuses a session with itself", () => {
    const { alice } = parties();
    expect(thrownBy(() => initiate(alice, alice.getPrekeyBundle(), new IdentityRegistry(), ALICE_DEVICE))).toBeInstanceOf(
      SelfSessionError
    );
  });

  it("draws the EK, then DHs, and nothing else", () => {
    const { alice, bundle } = parties();
    const noble = getPrimitives();
    const draws: Uint8Array[] = [];
    let recording = false;
    registerCryptoPrimitives({
      name: "recording",
      randomBytes: (n) => {
        const out = noble.randomBytes(n);
        if (recording) draws.push(out.slice());
        return out;
      },
    });
    recording = true;
    const { session_init, ratchet_state } = initiate(alice, bundle, new IdentityRegistry());
    recording = false;
    expect(draws.map((d) => d.length)).toEqual([32, 32]);
    expect(bytesToBase64(x25519PublicFromPrivate(draws[0]!))).toBe(session_init.ek_pub_b64);
    expect(x25519PublicFromPrivate(draws[1]!)).toEqual(ratchet_state.dh_self.pub32);
  });
});

describe("responder bootstrap", () => {
  it.each([undefined, 300])("interoperates with the initiator for the first message (opk %s)", (opkId) => {
    const { alice, bob, bundle } = parties(opkId === undefined ? {} : { opkId });
    const init = initiate(alice, bundle, new IdentityRegistry());
    const resp = respond(bob, init.session_init);
    expect(resp.used).toEqual(opkId === undefined ? { spk_id: 1 } : { spk_id: 1, opk_id: opkId });

    const m = ratchetEncrypt({ state: init.ratchet_state, plaintext: utf8("hi") });
    expect(ratchetDecrypt({ state: resp.ratchet_state, header: m.header, ciphertext_b64: m.ciphertext_b64 }).plaintext).toEqual(utf8("hi"));
    const r = ratchetEncrypt({ state: resp.ratchet_state, plaintext: utf8("hi back") });
    expect(ratchetDecrypt({ state: init.ratchet_state, header: r.header, ciphertext_b64: r.ciphertext_b64 }).plaintext).toEqual(
      utf8("hi back")
    );
  });

  it("consumes nothing: the prekey state is unchanged and a second bootstrap works", () => {
    const { alice, bob, bundle } = parties({ opkId: 300 });
    const init = initiate(alice, bundle, new IdentityRegistry());
    const before = JSON.stringify(bob.exportState());
    respond(bob, init.session_init);
    respond(bob, init.session_init);
    expect(JSON.stringify(bob.exportState())).toBe(before);
  });

  it("a one-time prekey this device no longer holds is unknown_opk; an unknown SPK is unknown_spk", () => {
    const { alice, bob, bundle } = parties({ opkId: 300 });
    const init = initiate(alice, bundle, new IdentityRegistry());
    bob.removeOneTimePrekey(300);
    const before = JSON.stringify(bob.exportState());
    const err = thrownBy(() => respond(bob, init.session_init));
    expect(err).toBeInstanceOf(UnknownPrekeyError);
    expect((err as UnknownPrekeyError).code).toBe("unknown_opk");
    expect(JSON.stringify(bob.exportState())).toBe(before);

    const spkErr = thrownBy(() => respond(bob, { ...init.session_init, spk_id: 9, used_opk: false, opk_id: undefined } as never));
    expect((spkErr as UnknownPrekeyError).code).toBe("unknown_spk");
  });

  it("a sidecar sender differing from the host's sender_device_id is device_mismatch", () => {
    const { alice, bob, bundle } = parties();
    const init = initiate(alice, bundle, new IdentityRegistry());
    expect(thrownBy(() => respond(bob, init.session_init, CAROL_DEVICE))).toBeInstanceOf(DeviceMismatchError);
    expect(thrownBy(() => respond(bob, { ...init.session_init, sender_device_id: CAROL_DEVICE }))).toBeInstanceOf(
      DeviceMismatchError
    );
  });

  it("a prekey manager for another device is device_mismatch", () => {
    const { alice, bundle } = parties();
    const init = initiate(alice, bundle, new IdentityRegistry());
    const carol = X3DHPrekeyManagerV2.create({ recipient_device_id: CAROL_DEVICE });
    expect(
      thrownBy(() =>
        x3dhResponderBootstrapV2({
          session_init: init.session_init,
          prekeys: carol,
          recipient_device_id: BOB_DEVICE,
          sender_device_id: ALICE_DEVICE,
        })
      )
    ).toBeInstanceOf(DeviceMismatchError);
  });

  it("the responder state does not alias the manager's signed prekey (alias regression)", () => {
    const { alice, bob, bundle } = parties();
    const init = initiate(alice, bundle, new IdentityRegistry());
    const { ratchet_state } = respond(bob, init.session_init);
    const spkBefore = bob.getCurrentSignedPrekey();
    ratchet_state.dh_self.priv32.fill(0);
    ratchet_state.dh_self.pub32.fill(0);
    expect(bob.getCurrentSignedPrekey()).toEqual(spkBefore);
    expect(bob.getCurrentSignedPrekey().priv32.some((b) => b !== 0)).toBe(true);
  });
});

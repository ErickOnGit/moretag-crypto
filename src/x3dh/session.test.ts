import { describe, it, expect } from "vitest";
import { IdentityRegistry } from "../identity/trust.js";
import { X3DHPrekeyManagerV1 } from "./prekey-manager.js";
import {
  x3dhInitiatorWithTrustV1,
  x3dhResponderWithPrekeysV1,
  x3dhInitiatorBootstrapV1,
  x3dhResponderBootstrapV1,
} from "./session.js";
import { x3dhInitiatorV1 } from "../crypto/x3dh.js";
import { generateX25519Keypair } from "../crypto/x25519.js";
import { generateEd25519Keypair } from "../crypto/ed25519.js";
import { ratchetEncrypt, ratchetDecrypt } from "../ratchet/ratchet.js";

function encode(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

describe("X3DH session wrappers", () => {
  it("pins recipient identity on first use and rejects mismatch", () => {
    const bob = new X3DHPrekeyManagerV1({ recipient_device_id: "bob-device" });
    bob.rotateSignedPrekey(1);
    const aliceIk = generateX25519Keypair();
    const trust = new IdentityRegistry();

    const bundle = bob.getPrekeyBundle();
    const init1 = x3dhInitiatorWithTrustV1({
      sender_device_id: "alice-device",
      recipient_bundle: bundle,
      initiator_ik_priv32: aliceIk.priv32,
      trust,
    });
    const resp1 = x3dhResponderWithPrekeysV1({ session_init: init1.session_init, prekeys: bob });
    expect(resp1.rk32).toEqual(init1.rk32);

    // Simulate identity mismatch: new IK for bob
    const bob2 = new X3DHPrekeyManagerV1({ recipient_device_id: "bob-device" });
    bob2.rotateSignedPrekey(1);
    const bundle2 = bob2.getPrekeyBundle();

    expect(() =>
      x3dhInitiatorWithTrustV1({
        sender_device_id: "alice-device",
        recipient_bundle: bundle2,
        initiator_ik_priv32: aliceIk.priv32,
        trust,
      })
    ).toThrow(/mismatch/);
  });

  it("device removal allows re-trust on next contact", () => {
    const bob = new X3DHPrekeyManagerV1({ recipient_device_id: "bob-device" });
    bob.rotateSignedPrekey(1);
    const trust = new IdentityRegistry();
    const aliceIk = generateX25519Keypair();

    x3dhInitiatorWithTrustV1({
      sender_device_id: "alice-device",
      recipient_bundle: bob.getPrekeyBundle(),
      initiator_ik_priv32: aliceIk.priv32,
      trust,
    });

    trust.remove("bob-device");

    // New bob identity should be accepted as new after removal
    const bob2 = new X3DHPrekeyManagerV1({ recipient_device_id: "bob-device" });
    bob2.rotateSignedPrekey(1);

    expect(() =>
      x3dhInitiatorWithTrustV1({
        sender_device_id: "alice-device",
        recipient_bundle: bob2.getPrekeyBundle(),
        initiator_ik_priv32: aliceIk.priv32,
        trust,
      })
    ).not.toThrow();
  });

  it("responder validates recipient_device_id against local prekeys", () => {
    const bob = new X3DHPrekeyManagerV1({ recipient_device_id: "bob-device" });
    bob.rotateSignedPrekey(1);

    const aliceIk = generateX25519Keypair();
    const { session_init } = x3dhInitiatorV1({
      sender_device_id: "alice-device",
      recipient_bundle: bob.getPrekeyBundle(),
      initiator_ik_priv32: aliceIk.priv32,
    });

    const wrongPrekeys = new X3DHPrekeyManagerV1({ recipient_device_id: "other-device" });
    wrongPrekeys.rotateSignedPrekey(1);

    expect(() =>
      x3dhResponderWithPrekeysV1({ session_init, prekeys: wrongPrekeys })
    ).toThrow(/recipient_device_id mismatch/);
  });

  it("responder requires the sender's signing key to pin two-key identity", () => {
    const bob = new X3DHPrekeyManagerV1({ recipient_device_id: "bob-device" });
    bob.rotateSignedPrekey(1);
    const trust = new IdentityRegistry();

    const alice1 = generateX25519Keypair();
    // session_init WITHOUT the sender's Ed25519 key cannot establish trust.
    const initNoSig = x3dhInitiatorV1({
      sender_device_id: "alice-device",
      recipient_bundle: bob.getPrekeyBundle(),
      initiator_ik_priv32: alice1.priv32,
    });
    expect(() =>
      x3dhResponderWithPrekeysV1({ session_init: initNoSig.session_init, prekeys: bob, trust })
    ).toThrow(/sender_ik_sig_pub_b64 is required/);
  });

  it("responder pins sender identity, blocks rotation, and accepts approveRotation", () => {
    const bob = new X3DHPrekeyManagerV1({ recipient_device_id: "bob-device" });
    bob.rotateSignedPrekey(1);
    const trust = new IdentityRegistry();

    const alice1 = generateX25519Keypair();
    const alice1Sig = generateEd25519Keypair();
    const init1 = x3dhInitiatorV1({
      sender_device_id: "alice-device",
      recipient_bundle: bob.getPrekeyBundle(),
      initiator_ik_priv32: alice1.priv32,
      initiator_ik_sig_pub32: alice1Sig.pub32,
    });
    expect(() =>
      x3dhResponderWithPrekeysV1({ session_init: init1.session_init, prekeys: bob, trust })
    ).not.toThrow();

    // A different sender identity is rejected (no silent rotation).
    const alice2 = generateX25519Keypair();
    const alice2Sig = generateEd25519Keypair();
    const init2 = x3dhInitiatorV1({
      sender_device_id: "alice-device",
      recipient_bundle: bob.getPrekeyBundle(),
      initiator_ik_priv32: alice2.priv32,
      initiator_ik_sig_pub32: alice2Sig.pub32,
    });
    expect(() =>
      x3dhResponderWithPrekeysV1({ session_init: init2.session_init, prekeys: bob, trust })
    ).toThrow(/mismatch/);
    expect(trust.isBlocked("alice-device")).toBe(true);

    // Out-of-band approval of the new identity unblocks subsequent contact.
    trust.approveRotation({
      device_id: "alice-device",
      ik_pub_b64: init2.session_init.sender_ik_pub_b64,
      ik_sig_pub_b64: init2.session_init.sender_ik_sig_pub_b64!,
    });
    expect(() =>
      x3dhResponderWithPrekeysV1({ session_init: init2.session_init, prekeys: bob, trust })
    ).not.toThrow();
  });

  it("bootstraps X3DH + ratchet states that interoperate for first message", () => {
    const bob = new X3DHPrekeyManagerV1({ recipient_device_id: "bob-device" });
    bob.rotateSignedPrekey(1);
    const aliceIk = generateX25519Keypair();

    const init = x3dhInitiatorBootstrapV1({
      sender_device_id: "alice-device",
      recipient_bundle: bob.getPrekeyBundle(),
      initiator_ik_priv32: aliceIk.priv32,
    });
    const resp = x3dhResponderBootstrapV1({
      session_init: init.session_init,
      prekeys: bob,
    });

    expect(resp.rk32).toEqual(init.rk32);

    const env = ratchetEncrypt({
      state: init.ratchet_state,
      plaintext: encode("hello"),
      sender_device_id: "alice-device",
      recipient_device_id: "bob-device",
    });
    const dec = ratchetDecrypt({
      state: resp.ratchet_state,
      header: env.header,
      ciphertext_b64: env.ciphertext_b64,
    });

    expect(new TextDecoder().decode(dec.plaintext)).toBe("hello");
  });
});

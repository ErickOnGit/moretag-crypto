import { describe, it, expect } from "vitest";
import { IdentityRegistry } from "../identity/trust.js";
import { X3DHPrekeyManagerV1 } from "./prekey-manager.js";
import { x3dhInitiatorWithTrustV1, x3dhResponderWithPrekeysV1 } from "./session.js";
import { generateX25519Keypair } from "../crypto/x25519.js";

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
});


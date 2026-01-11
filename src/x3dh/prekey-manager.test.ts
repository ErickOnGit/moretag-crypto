import { describe, it, expect } from "vitest";
import { X3DHPrekeyManagerV1 } from "./prekey-manager.js";
import { x3dhInitiatorV1 } from "../crypto/x3dh.js";
import { x3dhResponderWithPrekeysV1 } from "./session.js";
import { generateX25519Keypair } from "../crypto/x25519.js";

describe("X3DHPrekeyManagerV1", () => {
  it("creates a bundle and completes X3DH without OPK", () => {
    const bob = new X3DHPrekeyManagerV1({ recipient_device_id: "bob-device" });
    bob.rotateSignedPrekey(1);

    const bundle = bob.getPrekeyBundle();
    expect(bundle.opk_id).toBeUndefined();

    const aliceIk = generateX25519Keypair();
    const { session_init, rk32 } = x3dhInitiatorV1({
      sender_device_id: "alice-device",
      recipient_bundle: bundle,
      initiator_ik_priv32: aliceIk.priv32,
    });

    const resp = x3dhResponderWithPrekeysV1({ session_init, prekeys: bob });
    expect(resp.rk32).toEqual(rk32);
  });

  it("includes OPK when available and consumes it on responder", () => {
    const bob = new X3DHPrekeyManagerV1({ recipient_device_id: "bob-device" });
    bob.rotateSignedPrekey("spk-1");
    bob.addOneTimePrekeys({ startId: 100, count: 2 });

    const bundle = bob.getPrekeyBundle();
    expect(bundle.opk_id).toBe(100);

    const aliceIk = generateX25519Keypair();
    const { session_init, rk32 } = x3dhInitiatorV1({
      sender_device_id: "alice-device",
      recipient_bundle: bundle,
      initiator_ik_priv32: aliceIk.priv32,
    });
    expect(session_init.used_opk).toBe(true);
    expect(session_init.opk_id).toBe(100);

    const resp = x3dhResponderWithPrekeysV1({ session_init, prekeys: bob, consumeOpk: true });
    expect(resp.rk32).toEqual(rk32);

    // OPK 100 should be consumed, next bundle should expose 101
    const nextBundle = bob.getPrekeyBundle();
    expect(nextBundle.opk_id).toBe(101);
  });

  it("supports signed prekey rotation by id", () => {
    const bob = new X3DHPrekeyManagerV1({ recipient_device_id: "bob-device" });
    bob.rotateSignedPrekey(1);
    const b1 = bob.getPrekeyBundle();
    bob.rotateSignedPrekey(2);
    const b2 = bob.getPrekeyBundle();
    expect(b1.spk_id).toBe(1);
    expect(b2.spk_id).toBe(2);
  });
});


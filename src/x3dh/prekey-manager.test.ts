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

  describe("static create + lifecycle", () => {
    it("create() yields a usable bundle with the requested OPK count", () => {
      const bob = X3DHPrekeyManagerV1.create({
        recipient_device_id: "bob-device",
        initial_opk_count: 3,
      });
      expect(bob.getOneTimePrekeyCount()).toBe(3);
      const bundle = bob.getPrekeyBundle();
      expect(bundle.spk_id).toBe(1);
      expect(bundle.opk_id).toBe(1);
    });

    it("refill uses an internal monotonic id counter", () => {
      const bob = X3DHPrekeyManagerV1.create({
        recipient_device_id: "bob-device",
        initial_opk_count: 2,
      });
      expect(bob.shouldRefillOneTimePrekeys(2)).toBe(true);
      const minted = bob.refillOneTimePrekeys(3);
      expect(minted.map((r) => r.opk_id)).toEqual([3, 4, 5]);
      expect(bob.getOneTimePrekeyCount()).toBe(5);
      expect(bob.shouldRefillOneTimePrekeys(2)).toBe(false);
    });

    it("shouldRotateSignedPrekey honors the configured max age", () => {
      const bob = X3DHPrekeyManagerV1.create({
        recipient_device_id: "bob-device",
        initial_opk_count: 0,
        now_ms: 1000,
      });
      expect(bob.shouldRotateSignedPrekey(100, 1050)).toBe(false);
      expect(bob.shouldRotateSignedPrekey(100, 1200)).toBe(true);
    });
  });

  describe("exportState / fromState", () => {
    it("round-trips and the restored manager completes X3DH", () => {
      const bob = X3DHPrekeyManagerV1.create({
        recipient_device_id: "bob-device",
        initial_opk_count: 3,
      });
      const bundle = bob.getPrekeyBundle();

      const aliceIk = generateX25519Keypair();
      const { session_init, rk32 } = x3dhInitiatorV1({
        sender_device_id: "alice-device",
        recipient_bundle: bundle,
        initiator_ik_priv32: aliceIk.priv32,
      });

      // Persist + rebuild before responding (simulates app restart).
      const restored = X3DHPrekeyManagerV1.fromState(bob.exportState());
      const resp = x3dhResponderWithPrekeysV1({
        session_init,
        prekeys: restored,
        consumeOpk: true,
      });
      expect(resp.rk32).toEqual(rk32);
      // The consumed OPK is gone from the restored manager.
      expect(restored.getOneTimePrekeyCount()).toBe(2);
    });

    it("retains rotated (old) signed prekeys so past sessions still resolve", () => {
      const bob = X3DHPrekeyManagerV1.create({
        recipient_device_id: "bob-device",
        initial_opk_count: 0,
      });
      const oldBundle = bob.getPrekeyBundle(); // spk_id 1
      bob.rotateSignedPrekey(2);

      const aliceIk = generateX25519Keypair();
      const { session_init, rk32 } = x3dhInitiatorV1({
        sender_device_id: "alice-device",
        recipient_bundle: oldBundle, // references the now-old spk 1
        initiator_ik_priv32: aliceIk.priv32,
      });

      const restored = X3DHPrekeyManagerV1.fromState(bob.exportState());
      const resp = x3dhResponderWithPrekeysV1({ session_init, prekeys: restored });
      expect(resp.rk32).toEqual(rk32);
    });
  });
});


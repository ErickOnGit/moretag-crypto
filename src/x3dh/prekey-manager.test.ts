import { describe, it, expect } from "vitest";
import { X3DHPrekeyManagerV2, type X3DHPrekeyManagerStateV2 } from "./prekey-manager.js";
import { buildOpkBatchSigMessage, verifyPrekeyBundleV2 } from "../crypto/x3dh.js";
import { ed25519Verify } from "../crypto/ed25519.js";
import { decodeStrictBase64 } from "../encoding/base64.js";
import { InvalidDeviceIdError, UnknownPrekeyError } from "../errors.js";
import { BOB_DEVICE } from "../test-fixtures.js";

const fresh = (opks = 0) => X3DHPrekeyManagerV2.create({ recipient_device_id: BOB_DEVICE, initial_opk_count: opks });

function thrownBy(fn: () => unknown): unknown {
  try {
    fn();
  } catch (err) {
    return err;
  }
  throw new Error("expected a throw");
}

describe("X3DHPrekeyManagerV2", () => {
  it("needs a canonical device id", () => {
    expect(() => new X3DHPrekeyManagerV2({ recipient_device_id: "bob-device" })).toThrow(InvalidDeviceIdError);
  });

  it("create() makes signed prekey 1 and no one-time prekeys by default", () => {
    const bob = fresh();
    expect(bob.getCurrentSignedPrekey().spk_id).toBe(1);
    expect(bob.getOneTimePrekeyCount()).toBe(0);
    expect(fresh(3).getOneTimePrekeyCount()).toBe(3);
  });

  it("publishes a signed bundle with no one-time prekey", () => {
    const bundle = fresh(5).getPrekeyBundle();
    expect(bundle.v).toBe(2);
    expect(bundle).not.toHaveProperty("opk_id");
    expect(bundle).not.toHaveProperty("opk_pub_b64");
    expect(verifyPrekeyBundleV2(bundle, BOB_DEVICE).spk_id).toBe(1);
  });

  it("rotates signed prekeys to higher ids only, keeps old ones until removed", () => {
    const bob = fresh();
    const first = bob.getCurrentSignedPrekey();
    bob.rotateSignedPrekey(2);
    expect(bob.getPrekeyBundle().spk_id).toBe(2);
    expect(bob.getSignedPrekeyPriv32(1)).toEqual(first.priv32);
    expect(() => bob.rotateSignedPrekey(2)).toThrow(RangeError);
    expect(() => bob.rotateSignedPrekey(1)).toThrow(RangeError);
    expect(() => bob.rotateSignedPrekey(2 ** 31)).toThrow(RangeError);
    expect(() => bob.removeSignedPrekey(2)).toThrow();
    bob.removeSignedPrekey(1);
    bob.removeSignedPrekey(1); // idempotent
    expect((thrownBy(() => bob.getSignedPrekeyPriv32(1)) as UnknownPrekeyError).code).toBe("unknown_spk");
  });

  it("shouldRotateSignedPrekey honors the configured max age", () => {
    const bob = X3DHPrekeyManagerV2.create({ recipient_device_id: BOB_DEVICE, now_ms: 1_000 });
    expect(bob.shouldRotateSignedPrekey(500, 1_400)).toBe(false);
    expect(bob.shouldRotateSignedPrekey(500, 1_500)).toBe(true);
  });

  it("mints from max(next_opk_id, minNextId) and never reuses an id", () => {
    const bob = fresh();
    expect(bob.mintOneTimePrekeys(3).map((k) => k.opk_id)).toEqual([1, 2, 3]);
    expect(bob.mintOneTimePrekeys(2, 2).map((k) => k.opk_id)).toEqual([4, 5]);
    expect(bob.mintOneTimePrekeys(2, 100).map((k) => k.opk_id)).toEqual([100, 101]);
    bob.removeOneTimePrekey(101);
    expect(bob.mintOneTimePrekeys(1).map((k) => k.opk_id)).toEqual([102]);
    expect(bob.exportState().next_opk_id).toBe(103);
    expect(() => bob.mintOneTimePrekeys(2, 2 ** 31 - 1)).toThrow(RangeError);
  });

  it("lists one-time prekeys above an id, ascending", () => {
    const bob = fresh();
    bob.mintOneTimePrekeys(5);
    expect(bob.listOneTimePrekeysAbove(2).map((k) => k.opk_id)).toEqual([3, 4, 5]);
    expect(bob.listOneTimePrekeysAbove(5)).toEqual([]);
  });

  it("reading a one-time prekey does not consume it; remove is idempotent", () => {
    const bob = fresh(2);
    const priv = bob.getOneTimePrekeyPriv32(1);
    expect(bob.getOneTimePrekeyCount()).toBe(2);
    priv.fill(0); // a copy
    expect(bob.getOneTimePrekeyPriv32(1).some((b) => b !== 0)).toBe(true);
    expect(bob.removeOneTimePrekey(1)).toBe(true);
    expect(bob.removeOneTimePrekey(1)).toBe(false);
    expect(bob.hasOneTimePrekey(1)).toBe(false);
    expect((thrownBy(() => bob.getOneTimePrekeyPriv32(1)) as UnknownPrekeyError).code).toBe("unknown_opk");
  });

  it("signs a one-time prekey batch with the identity signing key over the batch message", () => {
    const bob = fresh();
    const keys = bob.mintOneTimePrekeys(3);
    const { prekeys, batch_sig_b64 } = bob.signOneTimePrekeyBatch([3, 1]);
    expect(prekeys.map((p) => p.opk_id)).toEqual([3, 1]);
    const message = buildOpkBatchSigMessage({
      device_id: BOB_DEVICE,
      prekeys: [
        { opk_id: 3, pub32: keys[2]!.pub32 },
        { opk_id: 1, pub32: keys[0]!.pub32 },
      ],
    });
    expect(ed25519Verify(bob.ik_sig.pub32, message, decodeStrictBase64("sig", batch_sig_b64))).toBe(true);
    expect((thrownBy(() => bob.signOneTimePrekeyBatch([9])) as UnknownPrekeyError).code).toBe("unknown_opk");
    expect(() => bob.signOneTimePrekeyBatch([])).toThrow(RangeError);
  });

  describe("exportState / fromState", () => {
    it("round-trips, keeping every signed prekey and the id counter", () => {
      const bob = fresh(2);
      bob.rotateSignedPrekey(5);
      bob.removeOneTimePrekey(2);
      const state = JSON.parse(JSON.stringify(bob.exportState())) as X3DHPrekeyManagerStateV2;
      const restored = X3DHPrekeyManagerV2.fromState(state);
      expect(restored.exportState()).toEqual(bob.exportState());
      expect(restored.getSignedPrekeyPriv32(1)).toEqual(bob.getSignedPrekeyPriv32(1));
      expect(restored.mintOneTimePrekeys(1)[0]!.opk_id).toBe(3);
    });

    it("rejects a malformed state, naming the field and never the value", () => {
      const good = () => JSON.parse(JSON.stringify(fresh(2).exportState()));
      const rows: Array<[string, (s: any) => void]> = [
        ["v", (s) => (s.v = 1)],
        ["recipient_device_id", (s) => (s.recipient_device_id = "bob-device")],
        ["ik_x25519_priv_b64", (s) => (s.ik_x25519_priv_b64 = "AAAA")],
        ["spks[0].spk_id", (s) => (s.spks[0].spk_id = "1")],
        ["opks[1].opk_id (duplicate)", (s) => (s.opks[1].opk_id = s.opks[0].opk_id)],
        ["opks[0].opk_id", (s) => (s.opks[0].opk_id = 0)],
        ["opks[0].pub32_b64", (s) => (s.opks[0].pub32_b64 = "AAAA")],
        ["current_spk_id", (s) => (s.current_spk_id = 9)],
        ["next_opk_id", (s) => (s.next_opk_id = 2)],
        ["next_opk_id", (s) => (s.next_opk_id = "3")],
      ];
      for (const [field, mutate] of rows) {
        const bad = good();
        mutate(bad);
        const err = thrownBy(() => X3DHPrekeyManagerV2.fromState(bad)) as Error;
        expect(err.message, field).toBe(`Corrupt prekey state: ${field}`);
        expect(err.message).not.toContain("bob-device");
      }
    });
  });
});

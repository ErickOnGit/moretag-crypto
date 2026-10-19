import { describe, it, expect } from "vitest";
import { IdentityRegistry } from "./trust.js";
import { IdentityMismatchError } from "../errors.js";
import { bytesToBase64 } from "../encoding/base64.js";

function key(bytes: number): string {
  const arr = new Uint8Array(32).fill(bytes);
  return bytesToBase64(arr);
}

describe("IdentityRegistry", () => {
  it("pins on first use and matches on repeat", () => {
    const reg = new IdentityRegistry();
    const r1 = reg.assertOrPin({ device_id: "d1", ik_pub_b64: key(1), ik_sig_pub_b64: key(2) });
    expect(r1.pinned_now).toBe(true);
    const r2 = reg.assertOrPin({ device_id: "d1", ik_pub_b64: key(1), ik_sig_pub_b64: key(2) });
    expect(r2.pinned_now).toBe(false);
    expect(reg.isBlocked("d1")).toBe(false);
  });

  it("blocks and throws on a changed DH identity key, without re-pinning", () => {
    const reg = new IdentityRegistry();
    reg.assertOrPin({ device_id: "d1", ik_pub_b64: key(1), ik_sig_pub_b64: key(2) });
    expect(() =>
      reg.assertOrPin({ device_id: "d1", ik_pub_b64: key(9), ik_sig_pub_b64: key(2) })
    ).toThrow(IdentityMismatchError);

    expect(reg.isBlocked("d1")).toBe(true);
    const rec = reg.get("d1");
    expect(rec?.ik_pub_b64).toBe(key(1)); // pinned identity unchanged
    expect(rec?.pending_ik_pub_b64).toBe(key(9));
  });

  it("blocks and throws on a changed signing identity key", () => {
    const reg = new IdentityRegistry();
    reg.assertOrPin({ device_id: "d1", ik_pub_b64: key(1), ik_sig_pub_b64: key(2) });
    expect(() =>
      reg.assertOrPin({ device_id: "d1", ik_pub_b64: key(1), ik_sig_pub_b64: key(8) })
    ).toThrow(IdentityMismatchError);
    expect(reg.isBlocked("d1")).toBe(true);
  });

  it("never silently rotates; approveRotation re-pins and clears blocked state", () => {
    const reg = new IdentityRegistry();
    reg.assertOrPin({ device_id: "d1", ik_pub_b64: key(1), ik_sig_pub_b64: key(2) });
    expect(() =>
      reg.assertOrPin({ device_id: "d1", ik_pub_b64: key(9), ik_sig_pub_b64: key(9) })
    ).toThrow(IdentityMismatchError);

    reg.approveRotation({ device_id: "d1", ik_pub_b64: key(9), ik_sig_pub_b64: key(9) });
    expect(reg.isBlocked("d1")).toBe(false);

    const ok = reg.assertOrPin({ device_id: "d1", ik_pub_b64: key(9), ik_sig_pub_b64: key(9) });
    expect(ok.pinned_now).toBe(false);
  });

  it("a later matching observation clears stale blocked/pending state", () => {
    const reg = new IdentityRegistry();
    reg.assertOrPin({ device_id: "d1", ik_pub_b64: key(1), ik_sig_pub_b64: key(2) });
    expect(() =>
      reg.assertOrPin({ device_id: "d1", ik_pub_b64: key(9), ik_sig_pub_b64: key(2) })
    ).toThrow(IdentityMismatchError);
    expect(reg.isBlocked("d1")).toBe(true);

    reg.assertOrPin({ device_id: "d1", ik_pub_b64: key(1), ik_sig_pub_b64: key(2) });
    const rec = reg.get("d1");
    expect(rec?.blocked_mismatch).toBe(false);
    expect(rec?.pending_ik_pub_b64).toBeUndefined();
  });

  it("round-trips through exportState / constructor", () => {
    const reg = new IdentityRegistry();
    reg.assertOrPin({ device_id: "d1", ik_pub_b64: key(1), ik_sig_pub_b64: key(2) });
    reg.assertOrPin({ device_id: "d2", ik_pub_b64: key(3), ik_sig_pub_b64: key(4) });

    const restored = new IdentityRegistry(reg.exportState());
    expect(restored.get("d1")?.ik_pub_b64).toBe(key(1));
    // A restored mismatch is still enforced.
    expect(() =>
      restored.assertOrPin({ device_id: "d2", ik_pub_b64: key(7), ik_sig_pub_b64: key(4) })
    ).toThrow(IdentityMismatchError);
  });

  it("rejects malformed keys", () => {
    const reg = new IdentityRegistry();
    expect(() =>
      reg.assertOrPin({ device_id: "d1", ik_pub_b64: "not-base64!!", ik_sig_pub_b64: key(2) })
    ).toThrow();
    expect(() =>
      reg.assertOrPin({ device_id: "d1", ik_pub_b64: bytesToBase64(new Uint8Array(16)), ik_sig_pub_b64: key(2) })
    ).toThrow(/32 bytes/);
  });
});

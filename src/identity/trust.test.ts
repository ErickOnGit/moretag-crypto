import { describe, it, expect } from "vitest";
import { IdentityRegistry } from "./trust.js";
import { bytesToBase64 } from "../encoding/base64.js";

function key(bytes: number): string {
  const arr = new Uint8Array(32).fill(bytes);
  return bytesToBase64(arr);
}

describe("IdentityRegistry", () => {
  it("pins on first use and matches on repeat", () => {
    const reg = new IdentityRegistry();
    const res1 = reg.trust("device-1", key(1));
    expect(res1).toBe("new");
    const res2 = reg.trust("device-1", key(1));
    expect(res2).toBe("match");
    reg.assertTrusted("device-1", key(1));
  });

  it("rejects mismatched identity unless rotation is allowed", () => {
    const reg = new IdentityRegistry();
    reg.trust("device-1", key(1));
    expect(() => reg.trust("device-1", key(2))).toThrow(/mismatch/);

    const rotateReg = new IdentityRegistry();
    rotateReg.trust("device-1", key(1));
    const res = rotateReg.trust("device-1", key(2), { allowRotate: true });
    expect(res).toBe("rotated");
    const rec = rotateReg.get("device-1");
    expect(rec?.rotations).toBe(1);
    rotateReg.assertTrusted("device-1", key(2));
  });
});

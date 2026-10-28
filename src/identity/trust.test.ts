import { describe, it, expect } from "vitest";
import { IdentityRegistry } from "./trust.js";
import { IdentityMismatchError } from "../errors.js";
import { bytesToBase64 } from "../encoding/base64.js";
import { ALICE_DEVICE, BOB_DEVICE } from "../test-fixtures.js";

function key(bytes: number): string {
  const arr = new Uint8Array(32).fill(bytes);
  return bytesToBase64(arr);
}

describe("IdentityRegistry", () => {
  it("pins on first use and matches on repeat", () => {
    const reg = new IdentityRegistry();
    const r1 = reg.assertOrPin({ device_id: ALICE_DEVICE, ik_pub_b64: key(1), ik_sig_pub_b64: key(2) });
    expect(r1.pinned_now).toBe(true);
    const r2 = reg.assertOrPin({ device_id: ALICE_DEVICE, ik_pub_b64: key(1), ik_sig_pub_b64: key(2) });
    expect(r2.pinned_now).toBe(false);
    expect(reg.isBlocked(ALICE_DEVICE)).toBe(false);
  });

  it("blocks and throws on a changed DH identity key, without re-pinning", () => {
    const reg = new IdentityRegistry();
    reg.assertOrPin({ device_id: ALICE_DEVICE, ik_pub_b64: key(1), ik_sig_pub_b64: key(2) });
    expect(() =>
      reg.assertOrPin({ device_id: ALICE_DEVICE, ik_pub_b64: key(9), ik_sig_pub_b64: key(2) })
    ).toThrow(IdentityMismatchError);

    expect(reg.isBlocked(ALICE_DEVICE)).toBe(true);
    const rec = reg.get(ALICE_DEVICE);
    expect(rec?.ik_pub_b64).toBe(key(1)); // pinned identity unchanged
    expect(rec?.pending_ik_pub_b64).toBe(key(9));
  });

  it("blocks and throws on a changed signing identity key", () => {
    const reg = new IdentityRegistry();
    reg.assertOrPin({ device_id: ALICE_DEVICE, ik_pub_b64: key(1), ik_sig_pub_b64: key(2) });
    expect(() =>
      reg.assertOrPin({ device_id: ALICE_DEVICE, ik_pub_b64: key(1), ik_sig_pub_b64: key(8) })
    ).toThrow(IdentityMismatchError);
    expect(reg.isBlocked(ALICE_DEVICE)).toBe(true);
  });

  it("never silently rotates; approveRotation re-pins and clears blocked state", () => {
    const reg = new IdentityRegistry();
    reg.assertOrPin({ device_id: ALICE_DEVICE, ik_pub_b64: key(1), ik_sig_pub_b64: key(2) });
    expect(() =>
      reg.assertOrPin({ device_id: ALICE_DEVICE, ik_pub_b64: key(9), ik_sig_pub_b64: key(9) })
    ).toThrow(IdentityMismatchError);

    reg.approveRotation({ device_id: ALICE_DEVICE, ik_pub_b64: key(9), ik_sig_pub_b64: key(9) });
    expect(reg.isBlocked(ALICE_DEVICE)).toBe(false);

    const ok = reg.assertOrPin({ device_id: ALICE_DEVICE, ik_pub_b64: key(9), ik_sig_pub_b64: key(9) });
    expect(ok.pinned_now).toBe(false);
  });

  it("a later matching observation clears stale blocked/pending state", () => {
    const reg = new IdentityRegistry();
    reg.assertOrPin({ device_id: ALICE_DEVICE, ik_pub_b64: key(1), ik_sig_pub_b64: key(2) });
    expect(() =>
      reg.assertOrPin({ device_id: ALICE_DEVICE, ik_pub_b64: key(9), ik_sig_pub_b64: key(2) })
    ).toThrow(IdentityMismatchError);
    expect(reg.isBlocked(ALICE_DEVICE)).toBe(true);

    reg.assertOrPin({ device_id: ALICE_DEVICE, ik_pub_b64: key(1), ik_sig_pub_b64: key(2) });
    const rec = reg.get(ALICE_DEVICE);
    expect(rec?.blocked_mismatch).toBe(false);
    expect(rec?.pending_ik_pub_b64).toBeUndefined();
  });

  it("round-trips through exportState / fromState, and the deprecated constructor argument", () => {
    const reg = new IdentityRegistry();
    reg.assertOrPin({ device_id: ALICE_DEVICE, ik_pub_b64: key(1), ik_sig_pub_b64: key(2) });
    reg.assertOrPin({ device_id: BOB_DEVICE, ik_pub_b64: key(3), ik_sig_pub_b64: key(4) });

    for (const restored of [IdentityRegistry.fromState(reg.exportState()), new IdentityRegistry(reg.exportState())]) {
      expect(restored.exportState()).toEqual(reg.exportState());
      expect(restored.get(ALICE_DEVICE)?.ik_pub_b64).toBe(key(1));
      // A restored mismatch is still enforced.
      expect(() =>
        restored.assertOrPin({ device_id: BOB_DEVICE, ik_pub_b64: key(7), ik_sig_pub_b64: key(4) })
      ).toThrow(IdentityMismatchError);
    }
  });

  it("rejects malformed keys", () => {
    const reg = new IdentityRegistry();
    expect(() =>
      reg.assertOrPin({ device_id: ALICE_DEVICE, ik_pub_b64: "not-base64!!", ik_sig_pub_b64: key(2) })
    ).toThrow();
    expect(() =>
      reg.assertOrPin({ device_id: ALICE_DEVICE, ik_pub_b64: bytesToBase64(new Uint8Array(16)), ik_sig_pub_b64: key(2) })
    ).toThrow(/32 bytes/);
  });

  it("check() reports unknown, match or mismatch and records nothing", () => {
    const reg = new IdentityRegistry();
    const pinned = { device_id: ALICE_DEVICE, ik_pub_b64: key(1), ik_sig_pub_b64: key(2) };
    expect(reg.check(pinned)).toBe("unknown");
    expect(reg.get(ALICE_DEVICE)).toBeNull();

    reg.assertOrPin(pinned);
    const before = JSON.stringify(reg.exportState());
    expect(reg.check(pinned)).toBe("match");
    expect(reg.check({ ...pinned, ik_pub_b64: key(3) })).toBe("mismatch");
    expect(reg.check({ ...pinned, ik_sig_pub_b64: key(3) })).toBe("mismatch");
    expect(JSON.stringify(reg.exportState())).toBe(before);
    expect(reg.isBlocked(ALICE_DEVICE)).toBe(false);
  });

  it("check() compares bytes, and refuses malformed keys", () => {
    const reg = new IdentityRegistry();
    reg.assertOrPin({ device_id: ALICE_DEVICE, ik_pub_b64: key(1), ik_sig_pub_b64: key(2) });
    expect(() => reg.check({ device_id: ALICE_DEVICE, ik_pub_b64: "AAAA", ik_sig_pub_b64: key(2) })).toThrow(TypeError);
  });
});

describe("IdentityRegistry.fromState: stored state is untrusted", () => {
  /** A device id that must never reach a message. */
  const SENTINEL = "5e471e1a-3c9e-4f1d-9b2a-7c6d5e4f3a21";
  // Canonical base64 needs the last character's two unused bits zero; "B" sets one.
  const NON_CANONICAL_32 = `${"A".repeat(42)}B=`;

  type Stored = { v: unknown; records: Record<string, Record<string, unknown>> };
  /** One plain record and one blocked record with pending keys, as JSON gives them back. */
  function good(): Stored {
    const reg = new IdentityRegistry();
    reg.assertOrPin({ device_id: SENTINEL, ik_pub_b64: key(1), ik_sig_pub_b64: key(2), now_ms: 1_000 });
    reg.assertOrPin({ device_id: BOB_DEVICE, ik_pub_b64: key(3), ik_sig_pub_b64: key(4), now_ms: 2_000 });
    expect(() =>
      reg.assertOrPin({ device_id: BOB_DEVICE, ik_pub_b64: key(5), ik_sig_pub_b64: key(4), now_ms: 3_000 })
    ).toThrow(IdentityMismatchError);
    return JSON.parse(JSON.stringify(reg.exportState())) as Stored;
  }
  const rec = (s: Stored) => s.records[SENTINEL]!;
  const blocked = (s: Stored) => s.records[BOB_DEVICE]!;

  it("accepts what exportState writes, blocked and pending records included", () => {
    const restored = IdentityRegistry.fromState(good());
    expect(restored.exportState()).toEqual(good());
    expect(restored.isBlocked(BOB_DEVICE)).toBe(true);
    expect(restored.isBlocked(SENTINEL)).toBe(false);
  });

  it("drops unknown fields", () => {
    const s = good();
    rec(s).extra = "x";
    expect(IdentityRegistry.fromState(s).get(SENTINEL)).not.toHaveProperty("extra");
  });

  /** Breaks the stored state in place. */
  const edit = (fn: (s: Stored) => unknown) => (s: Stored) => {
    fn(s);
    return s;
  };

  // [field named in the message, the broken stored state made from a good one]
  const rows: Array<[string, (s: Stored) => unknown]> = [
    ["root", () => null],
    ["root", () => []],
    ["v", (s) => ({ ...s, v: 2 })],
    ["v", (s) => ({ ...s, v: "1" })],
    ["records", (s) => ({ ...s, records: null })],
    ["records", (s) => ({ ...s, records: [] })],
    ["record", (s) => ({ ...s, records: { ...s.records, [SENTINEL]: "pinned" } })],
    ["device_id", (s) => ({ ...s, records: { [BOB_DEVICE]: rec(s) } })],
    ["device_id", (s) => ({ ...s, records: { [SENTINEL]: { ...rec(s), device_id: undefined } } })],
    ["device_id", (s) => ({ ...s, records: { "": { ...rec(s), device_id: "" } } })],
    ["device_id", (s) => ({ ...s, records: { ["x".repeat(257)]: { ...rec(s), device_id: "x".repeat(257) } } })],
    ["ik_pub_b64", edit((s) => (rec(s).ik_pub_b64 = bytesToBase64(new Uint8Array(31))))],
    ["ik_pub_b64", edit((s) => (rec(s).ik_pub_b64 = NON_CANONICAL_32))],
    ["ik_pub_b64", edit((s) => (rec(s).ik_pub_b64 = 7))],
    ["ik_pub_b64", edit((s) => delete rec(s).ik_pub_b64)],
    ["ik_sig_pub_b64", edit((s) => (rec(s).ik_sig_pub_b64 = bytesToBase64(new Uint8Array(33))))],
    ["ik_sig_pub_b64", edit((s) => (rec(s).ik_sig_pub_b64 = "not base64!"))],
    ["pinned_at_ms", edit((s) => (rec(s).pinned_at_ms = -1))],
    ["pinned_at_ms", edit((s) => (rec(s).pinned_at_ms = "1000"))],
    ["last_seen_at_ms", edit((s) => delete rec(s).last_seen_at_ms)],
    ["last_seen_at_ms", edit((s) => (rec(s).last_seen_at_ms = Infinity))],
    ["blocked_mismatch", edit((s) => (rec(s).blocked_mismatch = "no"))],
    ["blocked_mismatch", edit((s) => (rec(s).blocked_mismatch = 0))],
    ["blocked_mismatch", edit((s) => delete rec(s).blocked_mismatch)],
    ["pending_ik_pub_b64", edit((s) => (blocked(s).pending_ik_pub_b64 = NON_CANONICAL_32))],
    ["pending_ik_pub_b64", edit((s) => delete blocked(s).pending_ik_pub_b64)],
    ["pending_ik_sig_pub_b64", edit((s) => delete blocked(s).pending_ik_sig_pub_b64)],
    ["pending_seen_at_ms", edit((s) => delete blocked(s).pending_seen_at_ms)],
    ["pending_ik_sig_pub_b64", edit((s) => (rec(s).pending_ik_pub_b64 = key(9)))],
  ];

  it.each(rows)("rejects %s (row %#)", (field, breakIt) => {
    const state = breakIt(good());
    for (const load of [() => IdentityRegistry.fromState(state), () => new IdentityRegistry(state as never)]) {
      let err: unknown;
      try {
        load();
      } catch (e) {
        err = e;
      }
      expect(err).toBeInstanceOf(TypeError);
      expect((err as Error).message).toBe(`Corrupt identity state: ${field}`);
      expect((err as Error).message).not.toContain(SENTINEL);
    }
  });
});

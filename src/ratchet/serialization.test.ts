import { test, expect, describe } from "vitest";
import type { RatchetState } from "./ratchet.js";
import {
  serializeRatchetStateV2,
  deserializeRatchetStateV2,
  serializePersistedSessionV2,
  deserializePersistedSessionV2,
  type SerializedRatchetStateV2,
} from "./serialization.js";
import { bytesToBase64 } from "../encoding/base64.js";
import { MAX_SKIPPED_KEYS } from "../crypto/limits.js";
import { buildAssociatedDataV2 } from "../crypto/ad.js";
import { ALICE_DEVICE, BOB_DEVICE } from "../test-fixtures.js";

function bytes(seed: number, len = 32): Uint8Array {
  return new Uint8Array(Array.from({ length: len }, (_, i) => (seed + i) % 256));
}

/** A skipped-key id in the ratchet's grammar: base64(32-byte DH key):n. */
function skippedId(seed: number, n: number): string {
  return `${bytesToBase64(bytes(seed))}:${n}`;
}
const ID_A = skippedId(30, 0);
const ID_B = skippedId(40, 3);

const AD = buildAssociatedDataV2({
  initiator_ik_pub32: bytes(70),
  responder_ik_pub32: bytes(71),
  initiator_ik_sig_pub32: bytes(72),
  responder_ik_sig_pub32: bytes(73),
  initiator_device_id: ALICE_DEVICE,
  responder_device_id: BOB_DEVICE,
});

function sampleState(withSkipped: boolean): RatchetState {
  return {
    version: 2,
    role: "responder",
    ad: AD,
    rk32: bytes(1),
    ck_s32: bytes(2),
    ck_r32: bytes(3),
    ns: 5,
    nr: 7,
    pn: 2,
    dh_self: { priv32: bytes(4), pub32: bytes(5) },
    dh_remote_pub32: bytes(6),
    skipped: withSkipped
      ? new Map([
          [ID_A, bytes(10)],
          [ID_B, bytes(20)],
        ])
      : new Map(),
  };
}

test("round-trips a state through JSON, including a non-empty skipped map", () => {
  const state = sampleState(true);

  const json = JSON.stringify(serializeRatchetStateV2(state));
  const restored = deserializeRatchetStateV2(JSON.parse(json));

  expect(restored.version).toBe(2);
  expect(restored.role).toBe("responder");
  expect(restored.ad).toEqual(AD);
  expect(restored.rk32).toEqual(state.rk32);
  expect(restored.ck_s32).toEqual(state.ck_s32);
  expect(restored.ck_r32).toEqual(state.ck_r32);
  expect(restored.ns).toBe(5);
  expect(restored.nr).toBe(7);
  expect(restored.pn).toBe(2);
  expect(restored.dh_self.priv32).toEqual(state.dh_self.priv32);
  expect(restored.dh_self.pub32).toEqual(state.dh_self.pub32);
  expect(restored.dh_remote_pub32).toEqual(state.dh_remote_pub32);

  // The skipped Map is the case that breaks naive array round-tripping.
  expect(restored.skipped).toBeInstanceOf(Map);
  expect(restored.skipped.size).toBe(2);
  expect(restored.skipped.get(ID_A)).toEqual(bytes(10));
  expect(restored.skipped.get(ID_B)).toEqual(bytes(20));
});

test("handles undefined chain keys, no remote key and an empty skipped map", () => {
  const state: RatchetState = {
    ...sampleState(false),
    ck_s32: undefined,
    ck_r32: undefined,
    dh_remote_pub32: undefined,
  };

  const restored = deserializeRatchetStateV2(
    JSON.parse(JSON.stringify(serializeRatchetStateV2(state)))
  );

  expect(restored.ck_s32).toBeUndefined();
  expect(restored.ck_r32).toBeUndefined();
  expect(restored.dh_remote_pub32).toBeUndefined();
  expect(restored.skipped.size).toBe(0);
});

test("round-trips a PersistedSession with its optimistic version counter", () => {
  const record = { version: 42, state: sampleState(true) };

  const restored = deserializePersistedSessionV2(
    JSON.parse(JSON.stringify(serializePersistedSessionV2(record)))
  );

  expect(restored.version).toBe(42);
  expect(restored.state.skipped.get(ID_A)).toEqual(bytes(10));
});

describe("shape checks on a stored ratchet state", () => {
  type Mutable = Record<string, unknown> & { dh_self: Record<string, unknown> };
  const b64 = (len: number, seed = 50) => bytesToBase64(bytes(seed, len));
  const good = () =>
    JSON.parse(JSON.stringify(serializeRatchetStateV2(sampleState(true)))) as Mutable;
  const set = (field: string, value: unknown) => (s: Mutable) => {
    s[field] = value;
  };
  const setDh = (field: string, value: unknown) => (s: Mutable) => {
    s.dh_self[field] = value;
  };
  const setSkipped = (value: unknown) => (s: Mutable) => {
    s.skipped = value;
  };

  // [field named in the message, the stored value that breaks it, how it is stored]
  const rows: Array<[string, unknown, (s: Mutable) => void]> = [
    ["v", 1, set("v", 1)],
    ["role", "sender", set("role", "sender")],
    ["role", undefined, set("role", undefined)],
    ["ad_b64", b64(163), set("ad_b64", b64(163))],
    ["ad_b64", b64(164), set("ad_b64", b64(164))],
    ["ad_b64", null, set("ad_b64", null)],
    ["rk32_b64", b64(31), set("rk32_b64", b64(31))],
    ["rk32_b64", "not base64!", set("rk32_b64", "not base64!")],
    ["rk32_b64", 7, set("rk32_b64", 7)],
    ["ck_s32_b64", "", set("ck_s32_b64", "")],
    ["ck_s32_b64", b64(33), set("ck_s32_b64", b64(33))],
    ["ck_s32_b64", undefined, set("ck_s32_b64", undefined)],
    ["ck_r32_b64", "", set("ck_r32_b64", "")],
    ["ck_r32_b64", b64(16), set("ck_r32_b64", b64(16))],
    ["ns", -1, set("ns", -1)],
    ["ns", 1.5, set("ns", 1.5)],
    ["nr", 2 ** 53, set("nr", 2 ** 53)],
    ["nr", "3", set("nr", "3")],
    ["pn", -7, set("pn", -7)],
    ["dh_self", "a string", set("dh_self", "a string")],
    ["dh_self.priv32_b64", b64(31), setDh("priv32_b64", b64(31))],
    ["dh_self.pub32_b64", b64(64), setDh("pub32_b64", b64(64))],
    ["dh_remote_pub32_b64", b64(1), set("dh_remote_pub32_b64", b64(1))],
    ["dh_remote_pub32_b64", "", set("dh_remote_pub32_b64", "")],
    ["dh_remote_pub32_b64", undefined, set("dh_remote_pub32_b64", undefined)],
    ["skipped", "none", setSkipped("none")],
    ["skipped[0]", ["lonely"], setSkipped([["lonely"]])],
    ["skipped[0][0]", "key-a:0", setSkipped([["key-a:0", b64(32)]])],
    ["skipped[0][0]", `${b64(32)}:01`, setSkipped([[`${b64(32)}:01`, b64(32)]])],
    // The DH key's base64 must be canonical: "B" sets an unused bit.
    ["skipped[0][0]", `${"A".repeat(42)}B=:0`, setSkipped([[`${"A".repeat(42)}B=:0`, b64(32)]])],
    ["skipped[0][0]", `${b64(31)}:0`, setSkipped([[`${b64(31)}:0`, b64(32)]])],
    ["skipped[0][0]", `${b64(32)}:${2 ** 53}`, setSkipped([[`${b64(32)}:${2 ** 53}`, b64(32)]])],
    ["skipped[1][0] (duplicate)", ID_A, setSkipped([[ID_A, b64(32)], [ID_A, b64(32, 9)]])],
    ["skipped[0][1]", b64(31), setSkipped([[ID_A, b64(31)]])],
  ];

  test.each(rows)("rejects %s (%j)", (field, value, mutate) => {
    const bad = good();
    mutate(bad);
    let message = "";
    try {
      deserializeRatchetStateV2(bad as unknown as SerializedRatchetStateV2);
    } catch (err) {
      message = (err as Error).message;
    }
    expect(message).toBe(`Corrupt session state: ${field}`);
    if (typeof value === "string" && value !== "") expect(message).not.toContain(value);
  });

  test("accepts a skipped-key id at the largest safe message number", () => {
    const s = good();
    const id = `${b64(32)}:${Number.MAX_SAFE_INTEGER}`;
    s.skipped = [[id, b64(32)]];
    expect([...deserializeRatchetStateV2(s as unknown as SerializedRatchetStateV2).skipped.keys()]).toEqual([id]);
  });

  test("rejects a value that is not a plain object", () => {
    for (const bad of [null, [], "state", 1]) {
      expect(() => deserializeRatchetStateV2(bad as unknown as SerializedRatchetStateV2)).toThrow(
        /^Corrupt session state: root$/
      );
    }
  });

  test("accepts exactly MAX_SKIPPED_KEYS skipped keys and rejects one more", () => {
    const entries = Array.from(
      { length: MAX_SKIPPED_KEYS + 1 },
      (_, n): [string, string] => [skippedId(60, n), b64(32)]
    );
    const atCap = good();
    atCap.skipped = entries.slice(0, MAX_SKIPPED_KEYS);
    expect(
      deserializeRatchetStateV2(atCap as unknown as SerializedRatchetStateV2).skipped.size
    ).toBe(MAX_SKIPPED_KEYS);

    const over = good();
    over.skipped = entries;
    expect(() => deserializeRatchetStateV2(over as unknown as SerializedRatchetStateV2)).toThrow(
      /^Corrupt session state: skipped \(too many entries\)$/
    );
  });

  test("a persisted session checks its own version and counter, then the state", () => {
    const record = () =>
      JSON.parse(JSON.stringify(serializePersistedSessionV2({ version: 3, state: sampleState(false) })));
    const cases: Array<[string, (r: Record<string, any>) => void]> = [
      ["root", () => {}],
      ["v", (r) => (r.v = 1)],
      ["version", (r) => (r.version = -1)],
      ["version", (r) => (r.version = 0.5)],
      ["version", (r) => (r.version = "3")],
      ["state.rk32_b64", (r) => (r.state.rk32_b64 = b64(31))],
    ];
    for (const [field, mutate] of cases) {
      const bad = field === "root" ? null : record();
      if (bad) mutate(bad);
      expect(() => deserializePersistedSessionV2(bad), field).toThrow(
        new RegExp(`^Corrupt session state: ${field.replace(".", "\\.")}$`)
      );
    }
  });
});

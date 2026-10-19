import { test, expect } from "vitest";
import type { RatchetState } from "./ratchet.js";
import {
  serializeRatchetStateV1,
  deserializeRatchetStateV1,
  serializePersistedSessionV1,
  deserializePersistedSessionV1,
} from "./serialization.js";

function bytes(seed: number, len = 32): Uint8Array {
  return new Uint8Array(Array.from({ length: len }, (_, i) => (seed + i) % 256));
}

function sampleState(withSkipped: boolean): RatchetState {
  return {
    version: 1,
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
          ["key-a:0", bytes(10)],
          ["key-b:3", bytes(20)],
        ])
      : new Map(),
  };
}

test("round-trips a state through JSON, including a non-empty skipped map", () => {
  const state = sampleState(true);

  const json = JSON.stringify(serializeRatchetStateV1(state));
  const restored = deserializeRatchetStateV1(JSON.parse(json));

  expect(restored.version).toBe(1);
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
  expect(restored.skipped.get("key-a:0")).toEqual(bytes(10));
  expect(restored.skipped.get("key-b:3")).toEqual(bytes(20));
});

test("handles undefined chain keys and an empty skipped map", () => {
  const state: RatchetState = {
    ...sampleState(false),
    ck_s32: undefined,
    ck_r32: undefined,
  };

  const restored = deserializeRatchetStateV1(
    JSON.parse(JSON.stringify(serializeRatchetStateV1(state)))
  );

  expect(restored.ck_s32).toBeUndefined();
  expect(restored.ck_r32).toBeUndefined();
  expect(restored.skipped.size).toBe(0);
});

test("round-trips a PersistedSession with its optimistic version counter", () => {
  const record = { version: 42, state: sampleState(true) };

  const restored = deserializePersistedSessionV1(
    JSON.parse(JSON.stringify(serializePersistedSessionV1(record)))
  );

  expect(restored.version).toBe(42);
  expect(restored.state.skipped.get("key-a:0")).toEqual(bytes(10));
});

test("rejects an unknown serialization version", () => {
  const ok = serializeRatchetStateV1(sampleState(false));
  expect(() =>
    deserializeRatchetStateV1({ ...ok, v: 2 as unknown as 1 })
  ).toThrow(/Unsupported serialized ratchet state version/);
});

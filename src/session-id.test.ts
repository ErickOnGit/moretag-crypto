import { test, expect } from "vitest";
import { deriveDirectionScopedSessionIdV1 } from "./session-id.js";
import {
  ReplayDetectedError,
  SessionNotFoundError,
  RatchetStoreConflictError,
  IdentityMismatchError,
} from "./errors.js";
import { ALICE_DEVICE, BOB_DEVICE } from "./test-fixtures.js";

const pair = { my_device_id: ALICE_DEVICE, their_device_id: BOB_DEVICE } as const;

test("is deterministic for the same inputs", () => {
  const a = deriveDirectionScopedSessionIdV1({ ...pair, direction: "send" });
  const b = deriveDirectionScopedSessionIdV1({ ...pair, direction: "send" });
  expect(a).toBe(b);
  expect(a.startsWith("dr_")).toBe(true);
});

test("send and recv directions produce different ids", () => {
  const send = deriveDirectionScopedSessionIdV1({ ...pair, direction: "send" });
  const recv = deriveDirectionScopedSessionIdV1({ ...pair, direction: "recv" });
  expect(send).not.toBe(recv);
});

test("is not symmetric across device order", () => {
  const ab = deriveDirectionScopedSessionIdV1({ ...pair, direction: "send" });
  const ba = deriveDirectionScopedSessionIdV1({
    my_device_id: BOB_DEVICE,
    their_device_id: ALICE_DEVICE,
    direction: "send",
  });
  expect(ab).not.toBe(ba);
});

test("is url-safe (no +, /, or = in the encoded portion)", () => {
  const id = deriveDirectionScopedSessionIdV1({ ...pair, direction: "send" });
  expect(id).toMatch(/^dr_[A-Za-z0-9_-]+$/);
});

test("clamps max_len lower bound to 16 and is bounded by the digest length", () => {
  const tiny = deriveDirectionScopedSessionIdV1({ ...pair, direction: "send", max_len: 1 });
  const mid = deriveDirectionScopedSessionIdV1({ ...pair, direction: "send", max_len: 24 });
  const huge = deriveDirectionScopedSessionIdV1({ ...pair, direction: "send", max_len: 999 });
  // encoded portion = id minus the "dr_" prefix.
  expect(tiny.length - 3).toBe(16); // clamped up from 1 to the 16 minimum
  expect(mid.length - 3).toBe(24); // honored within the digest's encoded length
  expect(huge.length - 3).toBe(43); // SHA-256 base64url is 43 chars; can't exceed it
});

test("typed errors carry their name and defaults", () => {
  expect(new ReplayDetectedError().name).toBe("ReplayDetectedError");
  expect(new SessionNotFoundError().name).toBe("SessionNotFoundError");
  expect(new RatchetStoreConflictError().name).toBe("RatchetStoreConflictError");

  const mismatch = new IdentityMismatchError({
    deviceId: ALICE_DEVICE,
    pinnedIkPubB64: "p1",
    observedIkPubB64: "o1",
    pinnedIkSigPubB64: "p2",
    observedIkSigPubB64: "o2",
  });
  expect(mismatch).toBeInstanceOf(Error);
  expect(mismatch.name).toBe("IdentityMismatchError");
  expect(mismatch.deviceId).toBe(ALICE_DEVICE);
  expect(mismatch.observedIkSigPubB64).toBe("o2");
});

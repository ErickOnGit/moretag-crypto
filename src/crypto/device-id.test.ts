import { test, expect } from "vitest";
import {
  assertCanonicalDeviceId,
  deviceIdFromBytes,
  deviceIdToBytes,
  isCanonicalDeviceId,
} from "./device-id.js";
import { InvalidDeviceIdError } from "../errors.js";
import { ALICE_DEVICE } from "../test-fixtures.js";

test("a canonical lowercase UUID round-trips through its 16 raw bytes", () => {
  const bytes = deviceIdToBytes(ALICE_DEVICE);
  expect(bytes.byteLength).toBe(16);
  expect(Buffer.from(bytes).toString("hex")).toBe(ALICE_DEVICE.replace(/-/g, ""));
  expect(deviceIdFromBytes(bytes)).toBe(ALICE_DEVICE);
});

test("any version and variant is accepted, as Postgres prints a uuid", () => {
  expect(isCanonicalDeviceId("00000000-0000-0000-0000-000000000000")).toBe(true);
  expect(isCanonicalDeviceId("ffffffff-ffff-ffff-ffff-ffffffffffff")).toBe(true);
});

test("anything else is invalid_device_id", () => {
  const id = ALICE_DEVICE;
  const bad: unknown[] = [
    id.toUpperCase(),
    id.replace(/[a-f]/, (c) => c.toUpperCase()),
    `{${id}}`,
    `urn:uuid:${id}`,
    id.replace(/-/g, ""),
    ` ${id}`,
    `${id}\n`,
    id.slice(0, 35),
    `${id.slice(0, 35)}g`,
    `${id.slice(0, 35)}\ud800`,
    "",
    "alice-device",
    42,
    null,
    undefined,
  ];
  for (const value of bad) {
    expect(isCanonicalDeviceId(value)).toBe(false);
    let err: unknown;
    try {
      assertCanonicalDeviceId(value);
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(InvalidDeviceIdError);
    expect((err as InvalidDeviceIdError).code).toBe("invalid_device_id");
    expect((err as Error).message).not.toContain(id);
  }
});

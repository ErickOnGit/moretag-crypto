import { test, expect } from "vitest";
import { ASSOCIATED_DATA_V2_LENGTH, buildAssociatedDataV2, parseAssociatedDataV2 } from "./ad.js";
import { InvalidDeviceIdError, SelfSessionError } from "../errors.js";
import { ALICE_DEVICE, BOB_DEVICE } from "../test-fixtures.js";

const key = (fill: number) => new Uint8Array(32).fill(fill);
const parts = (devA = ALICE_DEVICE, devB = BOB_DEVICE) => ({
  initiator_ik_pub32: key(1),
  responder_ik_pub32: key(2),
  initiator_ik_sig_pub32: key(3),
  responder_ik_sig_pub32: key(4),
  initiator_device_id: devA,
  responder_device_id: devB,
});
const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");

test("layout: 0x05||IK_A, 0x05||IK_B, 0xED||IKsig_A, 0xED||IKsig_B, dev_A, dev_B = 164 bytes", () => {
  const ad = buildAssociatedDataV2(parts());
  expect(ASSOCIATED_DATA_V2_LENGTH).toBe(164);
  expect(ad.byteLength).toBe(164);
  expect(hex(ad)).toBe(
    "05" + "01".repeat(32) +
      "05" + "02".repeat(32) +
      "ed" + "03".repeat(32) +
      "ed" + "04".repeat(32) +
      ALICE_DEVICE.replace(/-/g, "") +
      BOB_DEVICE.replace(/-/g, "")
  );
});

test("parse round-trips and refuses a wrong length or type byte", () => {
  const ad = buildAssociatedDataV2(parts());
  expect(parseAssociatedDataV2(ad)).toEqual(parts());
  expect(() => parseAssociatedDataV2(ad.subarray(0, 163))).toThrow(TypeError);
  for (const at of [0, 33, 66, 99]) {
    const bad = new Uint8Array(ad);
    bad[at] = 0x06;
    expect(() => parseAssociatedDataV2(bad)).toThrow(TypeError);
  }
});

test("non-canonical device ids are invalid_device_id", () => {
  for (const bad of [ALICE_DEVICE.toUpperCase(), `{${ALICE_DEVICE}}`, `${ALICE_DEVICE.slice(0, 35)}\ud800`, ""]) {
    expect(() => buildAssociatedDataV2(parts(bad))).toThrow(InvalidDeviceIdError);
    expect(() => buildAssociatedDataV2(parts(ALICE_DEVICE, bad))).toThrow(InvalidDeviceIdError);
  }
});

test("equal device ids throw self_session", () => {
  let err: unknown;
  try {
    buildAssociatedDataV2(parts(ALICE_DEVICE, ALICE_DEVICE));
  } catch (e) {
    err = e;
  }
  expect(err).toBeInstanceOf(SelfSessionError);
  expect((err as SelfSessionError).code).toBe("self_session");
});

test("keys must be 32 bytes", () => {
  expect(() => buildAssociatedDataV2({ ...parts(), responder_ik_sig_pub32: new Uint8Array(31) })).toThrow(
    TypeError
  );
});

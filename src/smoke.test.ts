import { test, expect } from "vitest";
import { assertHeaderProtoV2, type HeaderProtoV2 } from "./wire/header.js";
import { InvalidWireError } from "./errors.js";
import { bytesToBase64 } from "./encoding/base64.js";
import { ALICE_DEVICE, BOB_DEVICE } from "./test-fixtures.js";

test("assertHeaderProtoV2 validates a correct minimal object", () => {
  const validHeader: HeaderProtoV2 = {
    v: 2,
    alg: "xchacha20poly1305",
    nonce_b64: bytesToBase64(new Uint8Array(24)),
    sender_device_id: ALICE_DEVICE,
    recipient_device_id: BOB_DEVICE,
    dr: { dh_pub_b64: bytesToBase64(new Uint8Array(32)), pn: 0, n: 1 },
  };
  expect(() => assertHeaderProtoV2(validHeader)).not.toThrow();
});

test("assertHeaderProtoV2 throws invalid_header on another version", () => {
  let err: unknown;
  try {
    assertHeaderProtoV2({ v: 1, alg: "xchacha20poly1305" });
  } catch (e) {
    err = e;
  }
  expect(err).toBeInstanceOf(InvalidWireError);
  expect((err as InvalidWireError).code).toBe("invalid_header");
  expect((err as Error).message).toBe("Invalid header: v");
});

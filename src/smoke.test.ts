import { test, expect } from "vitest";
import { assertHeaderProtoV1, type HeaderProtoV1 } from "./wire/header.js";

test("assertHeaderProtoV1 validates a correct minimal object", () => {
  const validHeader: HeaderProtoV1 = {
    v: 1,
    alg: "xchacha20poly1305",
    nonce_b64: "dummy_nonce",
    sender_device_id: "uuid-sender",
    recipient_device_id: "uuid-recipient",
    dr: {
      dh_pub_b64: "dummy_pub_key",
      pn: 0,
      n: 1,
    },
  };

  expect(() => assertHeaderProtoV1(validHeader)).not.toThrow();
});

test("assertHeaderProtoV1 throws on invalid version", () => {
  const invalidHeader = {
    v: 2,
    alg: "xchacha20poly1305",
    // other fields omitted for brevity, but type check fails fast
  };
  expect(() => assertHeaderProtoV1(invalidHeader)).toThrowError(
    "HeaderProtoV1.v must be 1"
  );
});

import { test, expect } from "vitest";
import { encodeAADFromHeaderV1 } from "./aad.js";
import type { HeaderProtoV1 } from "../wire/header.js";

// Helper to check buffer equality
function buffersEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false;
  for (let i = 0; i < a.byteLength; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

test("encodeAADFromHeaderV1 is deterministic", () => {
  const header1: HeaderProtoV1 = {
    v: 1,
    alg: "xchacha20poly1305",
    nonce_b64: "nonce",
    sender_device_id: "sender",
    recipient_device_id: "recipient",
    dr: { dh_pub_b64: "pub", pn: 0, n: 1 },
  };

  const header2: HeaderProtoV1 = {
    v: 1,
    alg: "xchacha20poly1305",
    nonce_b64: "nonce",
    sender_device_id: "sender",
    recipient_device_id: "recipient",
    dr: { dh_pub_b64: "pub", pn: 0, n: 1 },
  };

  // Ensure different object references but identical content
  expect(header1).not.toBe(header2);

  const encoded1 = encodeAADFromHeaderV1(header1);
  const encoded2 = encodeAADFromHeaderV1(header2);

  expect(buffersEqual(encoded1, encoded2)).toBe(true);
});

test("encodeAADFromHeaderV1 produces different output for different content", () => {
  const header1: HeaderProtoV1 = {
    v: 1,
    alg: "xchacha20poly1305",
    nonce_b64: "nonce",
    sender_device_id: "sender",
    recipient_device_id: "recipient",
    dr: { dh_pub_b64: "pub", pn: 0, n: 1 },
  };

  const header2 = { ...header1, sender_device_id: "sender2" };

  const encoded1 = encodeAADFromHeaderV1(header1);
  const encoded2 = encodeAADFromHeaderV1(header2);

  expect(buffersEqual(encoded1, encoded2)).toBe(false);
});

test("encodeAADFromHeaderV1 preserves non-plain objects and remains deterministic", () => {
  // Custom class instance (non-plain object)
  class Foo {
    constructor(public x: number) {}
  }

  // Create headers with extra fields containing non-plain objects
  // Cast to any to bypass TypeScript type checking for test purposes
  const header1: any = {
    v: 1,
    alg: "xchacha20poly1305",
    nonce_b64: "nonce",
    sender_device_id: "sender",
    recipient_device_id: "recipient",
    dr: { dh_pub_b64: "pub", pn: 0, n: 1 },
    // Non-plain objects that should be preserved as-is
    _testBytes: new Uint8Array([1, 2, 3]),
    _testClass: new Foo(123),
  };

  const header2: any = {
    v: 1,
    alg: "xchacha20poly1305",
    nonce_b64: "nonce",
    sender_device_id: "sender",
    recipient_device_id: "recipient",
    dr: { dh_pub_b64: "pub", pn: 0, n: 1 },
    // Same non-plain objects as header1
    _testBytes: new Uint8Array([1, 2, 3]),
    _testClass: new Foo(123),
  };

  const encoded1 = encodeAADFromHeaderV1(header1);
  const encoded2 = encodeAADFromHeaderV1(header2);

  // Deterministic for semantically identical objects
  expect(buffersEqual(encoded1, encoded2)).toBe(true);
});

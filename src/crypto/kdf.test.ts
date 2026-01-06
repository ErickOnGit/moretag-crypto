import { test, expect } from "vitest";
import { kdfRootAndChainKey, kdfChainKey } from "./kdf.js";
import { randomBytes } from "@noble/ciphers/utils.js";

// Helper to compare byte arrays
function buffersEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false;
  for (let i = 0; i < a.byteLength; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

test("kdfRootAndChainKey is deterministic for same inputs", () => {
  const rk = randomBytes(32);
  const dhOut = randomBytes(32);

  const result1 = kdfRootAndChainKey(rk, dhOut);
  const result2 = kdfRootAndChainKey(rk, dhOut);

  expect(buffersEqual(result1.rk32, result2.rk32)).toBe(true);
  expect(buffersEqual(result1.ck32, result2.ck32)).toBe(true);
});

test("kdfRootAndChainKey produces 32-byte outputs", () => {
  const rk = randomBytes(32);
  const dhOut = randomBytes(32);

  const result = kdfRootAndChainKey(rk, dhOut);

  expect(result.rk32.byteLength).toBe(32);
  expect(result.ck32.byteLength).toBe(32);
});

test("kdfRootAndChainKey produces different outputs for different inputs", () => {
  const rk = randomBytes(32);
  const dhOut1 = randomBytes(32);
  const dhOut2 = randomBytes(32);

  const result1 = kdfRootAndChainKey(rk, dhOut1);
  const result2 = kdfRootAndChainKey(rk, dhOut2);

  expect(buffersEqual(result1.rk32, result2.rk32)).toBe(false);
  expect(buffersEqual(result1.ck32, result2.ck32)).toBe(false);
});

test("kdfChainKey is deterministic for same input", () => {
  const ck = randomBytes(32);

  const result1 = kdfChainKey(ck);
  const result2 = kdfChainKey(ck);

  expect(buffersEqual(result1.ck32, result2.ck32)).toBe(true);
  expect(buffersEqual(result1.mk32, result2.mk32)).toBe(true);
});

test("kdfChainKey produces 32-byte outputs", () => {
  const ck = randomBytes(32);

  const result = kdfChainKey(ck);

  expect(result.ck32.byteLength).toBe(32);
  expect(result.mk32.byteLength).toBe(32);
});

test("kdfChainKey produces different outputs for different inputs", () => {
  const ck1 = randomBytes(32);
  const ck2 = randomBytes(32);

  const result1 = kdfChainKey(ck1);
  const result2 = kdfChainKey(ck2);

  expect(buffersEqual(result1.ck32, result2.ck32)).toBe(false);
  expect(buffersEqual(result1.mk32, result2.mk32)).toBe(false);
});

test("kdfChainKey chain: successive calls produce different chain keys", () => {
  const ck0 = randomBytes(32);

  const result1 = kdfChainKey(ck0);
  const result2 = kdfChainKey(result1.ck32);
  const result3 = kdfChainKey(result2.ck32);

  // All chain keys should be different
  expect(buffersEqual(ck0, result1.ck32)).toBe(false);
  expect(buffersEqual(result1.ck32, result2.ck32)).toBe(false);
  expect(buffersEqual(result2.ck32, result3.ck32)).toBe(false);

  // All message keys should be different
  expect(buffersEqual(result1.mk32, result2.mk32)).toBe(false);
  expect(buffersEqual(result2.mk32, result3.mk32)).toBe(false);
});

test("different KDF domains produce different outputs (implicitly tested)", () => {
  // kdfRootAndChainKey uses "moretag/v1/rkck"
  // kdfChainKey uses "moretag/v1/ckmk"
  // This test verifies they produce different outputs for the same input

  const input = randomBytes(32);

  // Use same input for both KDFs
  const rootResult = kdfRootAndChainKey(input, input);
  const chainResult = kdfChainKey(input);

  // Outputs should be different due to different domain strings
  expect(buffersEqual(rootResult.rk32, chainResult.ck32)).toBe(false);
  expect(buffersEqual(rootResult.ck32, chainResult.mk32)).toBe(false);
});

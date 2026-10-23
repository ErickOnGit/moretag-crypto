import { test, expect } from "vitest";
import { bytesToBase64, decodeStrictBase64 } from "./base64.js";

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

test("canonical encodings of every padding shape round-trip", () => {
  for (let len = 1; len <= 34; len++) {
    const bytes = Uint8Array.from({ length: len }, (_, i) => (i * 37 + len) & 0xff);
    expect(decodeStrictBase64("value", bytesToBase64(bytes))).toEqual(bytes);
  }
  expect(decodeStrictBase64("value", "AA==")).toEqual(new Uint8Array([0]));
  expect(decodeStrictBase64("value", "AAA=")).toEqual(new Uint8Array([0, 0]));
});

test("a non-canonical encoding (non-zero padding bits) is refused", () => {
  // Each decodes, in a lenient decoder, to the same bytes as a canonical string.
  for (const bad of ["AB==", "QR==", "AP==", "AAB=", "AAD=", "QUJ="]) {
    expect(() => decodeStrictBase64("value", bad), bad).toThrow(/^Invalid value: not valid base64$/);
  }
});

test("two spellings of one 32-byte key: only the canonical one decodes", () => {
  const key = Uint8Array.from({ length: 32 }, (_, i) => i * 7);
  const canonical = bytesToBase64(key);
  const last = ALPHABET.indexOf(canonical[42]!);
  const twin = `${canonical.slice(0, 42)}${ALPHABET[last | 1]}=`;
  expect(twin).not.toBe(canonical);
  expect(decodeStrictBase64("key", canonical)).toEqual(key);
  expect(() => decodeStrictBase64("key", twin)).toThrow(/not valid base64/);
});

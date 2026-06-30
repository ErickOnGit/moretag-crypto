import { test, expect } from "vitest";
import { sealAttachmentV1, openAttachmentV1 } from "./seal.js";
import { randomKey32, randomNonce24 } from "./aead.js";
import { bytesToBase64 } from "../encoding/base64.js";

test("attachment roundtrip returns original bytes", () => {
  const plaintext = new TextEncoder().encode("encrypted file body");

  const sealed = sealAttachmentV1({ plaintext });

  expect(sealed.ciphertext).toBeInstanceOf(Uint8Array);
  expect(sealed.ciphertext.byteLength).toBeGreaterThan(plaintext.byteLength); // + tag
  expect(new TextDecoder().decode(openAttachmentV1(sealed))).toBe(
    "encrypted file body"
  );
});

test("generates a fresh 32-byte key and 24-byte nonce by default", () => {
  const sealed = sealAttachmentV1({ plaintext: new Uint8Array([1, 2, 3]) });

  expect(Array.from(atobToBytes(sealed.key_b64)).length).toBe(32);
  expect(Array.from(atobToBytes(sealed.nonce_b64)).length).toBe(24);

  const other = sealAttachmentV1({ plaintext: new Uint8Array([1, 2, 3]) });
  expect(other.key_b64).not.toBe(sealed.key_b64); // unique key per attachment
});

test("honors caller-provided key and nonce", () => {
  const key32 = randomKey32();
  const nonce24 = randomNonce24();
  const plaintext = new Uint8Array([9, 8, 7, 6]);

  const sealed = sealAttachmentV1({ plaintext, key32, nonce24 });

  expect(sealed.key_b64).toBe(bytesToBase64(key32));
  expect(sealed.nonce_b64).toBe(bytesToBase64(nonce24));
  expect(openAttachmentV1(sealed)).toEqual(plaintext);
});

test("rejects a tampered key", () => {
  const sealed = sealAttachmentV1({
    plaintext: new TextEncoder().encode("top secret"),
  });

  const wrongKey = atobToBytes(sealed.key_b64);
  wrongKey[0] ^= 1;

  expect(() =>
    openAttachmentV1({ ...sealed, key_b64: bytesToBase64(wrongKey) })
  ).toThrow();
});

test("rejects tampered ciphertext", () => {
  const sealed = sealAttachmentV1({
    plaintext: new TextEncoder().encode("top secret"),
  });

  sealed.ciphertext[0] ^= 1;

  expect(() => openAttachmentV1(sealed)).toThrow();
});

// Small helper: decode base64 to bytes for length assertions without importing
// the strict decoder (keeps the test independent of internal validation rules).
function atobToBytes(b64: string): Uint8Array {
  const bin = Buffer.from(b64, "base64");
  return new Uint8Array(bin);
}

import { test, expect } from "vitest";
import {
  randomNonce24,
  aeadEncryptXChaCha20Poly1305,
  aeadDecryptXChaCha20Poly1305,
  assertKeyNonceLengths,
} from "./aead.js";
import { randomBytes } from "@noble/ciphers/utils.js";

test("XChaCha20-Poly1305 roundtrip", () => {
  const KEY = randomBytes(32);
  const NONCE = randomNonce24();
  const PLAINTEXT = new TextEncoder().encode("Hello, World!");
  const AAD = new TextEncoder().encode("metadata");

  const ciphertext = aeadEncryptXChaCha20Poly1305(KEY, NONCE, PLAINTEXT, AAD);
  const decrypted = aeadDecryptXChaCha20Poly1305(KEY, NONCE, ciphertext, AAD);

  expect(decrypted).toEqual(PLAINTEXT);
});

test("decrypt throws if ciphertext is tampered", () => {
  const KEY = randomBytes(32);
  const NONCE = randomNonce24();
  const PLAINTEXT = new TextEncoder().encode("Hello, World!");
  const AAD = new TextEncoder().encode("metadata");

  const ciphertext = aeadEncryptXChaCha20Poly1305(KEY, NONCE, PLAINTEXT, AAD);
  // Flip the last bit
  if (ciphertext.length > 0) {
    ciphertext[ciphertext.length - 1]! ^= 1;
  }

  expect(() =>
    aeadDecryptXChaCha20Poly1305(KEY, NONCE, ciphertext, AAD)
  ).toThrow();
});

test("decrypt throws if AAD is tampered", () => {
  const KEY = randomBytes(32);
  const NONCE = randomNonce24();
  const PLAINTEXT = new TextEncoder().encode("Hello, World!");
  const AAD = new TextEncoder().encode("metadata");

  const ciphertext = aeadEncryptXChaCha20Poly1305(KEY, NONCE, PLAINTEXT, AAD);
  const badAAD = new TextEncoder().encode("bad metadata");

  expect(() =>
    aeadDecryptXChaCha20Poly1305(KEY, NONCE, ciphertext, badAAD)
  ).toThrow();
});

test("decrypt throws with wrong key", () => {
  const KEY = randomBytes(32);
  const NONCE = randomNonce24();
  const PLAINTEXT = new TextEncoder().encode("Hello, World!");
  const AAD = new TextEncoder().encode("metadata");

  const ciphertext = aeadEncryptXChaCha20Poly1305(KEY, NONCE, PLAINTEXT, AAD);
  const wrongKey = randomBytes(32);

  expect(() =>
    aeadDecryptXChaCha20Poly1305(wrongKey, NONCE, ciphertext, AAD)
  ).toThrow();
});

test("length enforcement", () => {
  const KEY = randomBytes(32);
  const NONCE = randomNonce24();
  const PLAINTEXT = new TextEncoder().encode("Hello, World!");
  const AAD = new TextEncoder().encode("metadata");

  const shortKey = new Uint8Array(31);
  const longNonce = new Uint8Array(25);

  expect(() => assertKeyNonceLengths(shortKey, NONCE)).toThrow(/key length/);
  expect(() => assertKeyNonceLengths(KEY, longNonce)).toThrow(/nonce length/);

  expect(() =>
    aeadEncryptXChaCha20Poly1305(shortKey, NONCE, PLAINTEXT, AAD)
  ).toThrow();
  expect(() =>
    aeadDecryptXChaCha20Poly1305(KEY, longNonce, new Uint8Array(0), AAD)
  ).toThrow();
});

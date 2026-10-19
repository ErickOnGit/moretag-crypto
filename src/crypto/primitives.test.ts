import { describe, it, expect, afterEach } from "vitest";
import {
  registerCryptoPrimitives,
  resetCryptoPrimitives,
  getPrimitives,
  getCryptoPrimitivesProviderName,
  type CryptoPrimitivesProvider,
} from "./primitives.js";
import { randomBytes } from "@noble/ciphers/utils.js";
import {
  aeadEncryptXChaCha20Poly1305,
  aeadDecryptXChaCha20Poly1305,
  randomNonce24,
} from "./aead.js";

const csprng = (length: number) => randomBytes(length);

afterEach(() => {
  resetCryptoPrimitives();
});

describe("registerCryptoPrimitives", () => {
  it("defaults to noble", () => {
    expect(getCryptoPrimitivesProviderName()).toBe("noble");
  });

  it("rejects a provider without a randomBytes function", () => {
    expect(() =>
      registerCryptoPrimitives({ name: "no-rng" } as CryptoPrimitivesProvider)
    ).toThrow(/CSPRNG/);
    expect(getCryptoPrimitivesProviderName()).toBe("noble");
  });

  it("rejects a provider whose randomBytes is not random", () => {
    expect(() =>
      registerCryptoPrimitives({
        name: "constant-rng",
        randomBytes: (length) => new Uint8Array(length).fill(7),
      })
    ).toThrow(/not random/);
    expect(getCryptoPrimitivesProviderName()).toBe("noble");
  });

  it("rejects a provider whose randomBytes returns the wrong length", () => {
    expect(() =>
      registerCryptoPrimitives({
        name: "short-rng",
        randomBytes: () => randomBytes(16),
      })
    ).toThrow(/requested length/);
  });

  it("rejects a primitive that diverges from the reference implementation", () => {
    expect(() =>
      registerCryptoPrimitives({
        name: "broken-aead",
        randomBytes: csprng,
        xchacha20poly1305Encrypt: (key32, nonce24, plaintext) =>
          // Wrong construction: ignores AAD, fake tag
          new Uint8Array(plaintext.length + 16).fill(1),
      })
    ).toThrow(/xchacha20poly1305Encrypt diverges/);
    expect(getCryptoPrimitivesProviderName()).toBe("noble");
  });

  it("rejects a decrypt that does not throw on tampered ciphertext", () => {
    const noble = getPrimitives();
    expect(() =>
      registerCryptoPrimitives({
        name: "no-auth-aead",
        randomBytes: csprng,
        // Correct on the happy path, but swallows auth failures.
        xchacha20poly1305Decrypt: (key32, nonce24, ciphertext, aad) => {
          try {
            return noble.xchacha20poly1305Decrypt(key32, nonce24, ciphertext, aad);
          } catch {
            return new Uint8Array(0);
          }
        },
      })
    ).toThrow(/auth failure must throw/);
  });

  it("merges a partial provider over the noble defaults", () => {
    let aeadCalls = 0;
    const noble = getPrimitives();
    registerCryptoPrimitives({
      name: "partial",
      randomBytes: csprng,
      xchacha20poly1305Encrypt: (key32, nonce24, plaintext, aad) => {
        aeadCalls += 1;
        return noble.xchacha20poly1305Encrypt(key32, nonce24, plaintext, aad);
      },
    });
    expect(getCryptoPrimitivesProviderName()).toBe("partial");

    const key = randomBytes(32);
    const nonce = randomNonce24();
    const pt = new TextEncoder().encode("hello");
    const aad = new TextEncoder().encode("aad");
    const callsAfterSelfTest = aeadCalls;
    const ct = aeadEncryptXChaCha20Poly1305(key, nonce, pt, aad);
    expect(aeadCalls).toBe(callsAfterSelfTest + 1);
    // Unoverridden primitives (decrypt here) still work via the defaults.
    expect(aeadDecryptXChaCha20Poly1305(key, nonce, ct, aad)).toEqual(pt);
  });

  it("resetCryptoPrimitives restores noble", () => {
    registerCryptoPrimitives({ name: "temp", randomBytes: csprng });
    expect(getCryptoPrimitivesProviderName()).toBe("temp");
    resetCryptoPrimitives();
    expect(getCryptoPrimitivesProviderName()).toBe("noble");
  });
});

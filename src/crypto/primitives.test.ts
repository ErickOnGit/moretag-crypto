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
import {
  RFC5869_A1,
  RFC5869_A3,
  RFC7748_6_1,
  RFC8032_7_1_TEST1,
  XCHACHA_DRAFT03_A3_1,
} from "./known-answers.js";

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
    ).toThrow(/xchacha20poly1305Encrypt.* diverges/);
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

describe("self-test coverage", () => {
  const noble = getPrimitives(); // module load runs before any registration
  const flip = (b: Uint8Array) => {
    const c = b.slice();
    c[0] = (c[0] ?? 0) ^ 1;
    return c;
  };

  const cases: Array<[string, Omit<CryptoPrimitivesProvider, "name" | "randomBytes">, RegExp]> = [
    [
      "HKDF length 32",
      {
        hkdfSha256: (ikm, salt, info, length) => {
          const out = noble.hkdfSha256(ikm, salt, info, length);
          return length === 32 ? flip(out) : out;
        },
      },
      /hkdfSha256 .*diverges/,
    ],
    [
      "an empty AAD",
      {
        xchacha20poly1305Encrypt: (key, nonce, pt, aad) => {
          const out = noble.xchacha20poly1305Encrypt(key, nonce, pt, aad);
          return aad.length === 0 ? flip(out) : out;
        },
      },
      /xchacha20poly1305Encrypt \(empty AAD\) diverges/,
    ],
    [
      "an empty plaintext",
      {
        xchacha20poly1305Encrypt: (key, nonce, pt, aad) => {
          const out = noble.xchacha20poly1305Encrypt(key, nonce, pt, aad);
          return pt.length === 0 ? flip(out) : out;
        },
      },
      /xchacha20poly1305Encrypt \(empty plaintext\) diverges/,
    ],
    [
      "a large plaintext",
      {
        xchacha20poly1305Encrypt: (key, nonce, pt, aad) => {
          const out = noble.xchacha20poly1305Encrypt(key, nonce, pt, aad);
          return pt.length >= 16_500 ? flip(out) : out;
        },
      },
      /xchacha20poly1305Encrypt \(16,500-byte plaintext\) diverges/,
    ],
    [
      "an empty message to sign (RFC 8032 test 1)",
      {
        ed25519Sign: (seed, message) => {
          const out = noble.ed25519Sign(seed, message);
          return message.length === 0 ? flip(out) : out;
        },
      },
      /ed25519Sign diverges/,
    ],
  ];

  it.each(cases)("rejects a provider that diverges only at %s", (_label, overrides, expected) => {
    expect(() =>
      registerCryptoPrimitives({ name: "almost-right", randomBytes: csprng, ...overrides })
    ).toThrow(expected);
    expect(getCryptoPrimitivesProviderName()).toBe("noble");
  });

  it("@noble passes every published constant", () => {
    const clamp = (k: Uint8Array) => {
      const c = k.slice();
      c[0] = (c[0] ?? 0) & 248;
      c[31] = ((c[31] ?? 0) & 127) | 64;
      return c;
    };
    const x = RFC7748_6_1;
    expect(noble.x25519GetPublicKey(clamp(x.alicePriv))).toEqual(x.alicePub);
    expect(noble.x25519GetPublicKey(clamp(x.bobPriv))).toEqual(x.bobPub);
    expect(noble.x25519SharedSecret(clamp(x.alicePriv), x.bobPub)).toEqual(x.shared);
    expect(noble.x25519SharedSecret(clamp(x.bobPriv), x.alicePub)).toEqual(x.shared);

    const ed = RFC8032_7_1_TEST1;
    expect(noble.ed25519GetPublicKey(ed.seed)).toEqual(ed.pub);
    expect(noble.ed25519Sign(ed.seed, ed.message)).toEqual(ed.sig);
    expect(noble.ed25519Verify(ed.pub, ed.message, ed.sig)).toBe(true);

    const a1 = RFC5869_A1;
    expect(noble.hkdfSha256(a1.ikm, a1.salt, a1.info, 42)).toEqual(a1.okm);
    expect(noble.hkdfSha256(a1.ikm, a1.salt, a1.info, 32)).toEqual(a1.okm.subarray(0, 32));
    const a3 = RFC5869_A3;
    expect(noble.hkdfSha256(a3.ikm, a3.salt, a3.info, 42)).toEqual(a3.okm);

    const xc = XCHACHA_DRAFT03_A3_1;
    expect(noble.xchacha20poly1305Encrypt(xc.key, xc.nonce, xc.plaintext, xc.aad)).toEqual(xc.sealed);
    expect(noble.xchacha20poly1305Decrypt(xc.key, xc.nonce, xc.sealed, xc.aad)).toEqual(xc.plaintext);
  });
});

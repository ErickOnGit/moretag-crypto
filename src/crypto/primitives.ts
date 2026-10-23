/**
 * Pluggable low-level crypto primitives.
 *
 * moretag-crypto ships pure-JS implementations (@noble) so the package stays
 * free of native dependencies. Hosts with a faster backend (e.g. a JSI-bound
 * BoringSSL on React Native, where Hermes runs pure JS 10-50x slower than a
 * JIT VM) may override any subset via registerCryptoPrimitives(); primitives
 * not supplied keep the @noble defaults.
 *
 * Provider contract — normalized so key material and ciphertext interop
 * exactly across backends:
 * - x25519 scalars handed to a provider are already clamped (RFC 7748).
 *   Wrappers additionally reject all-zero shared secrets regardless of
 *   backend, so low-order peer keys fail identically everywhere.
 * - ed25519Sign takes the 32-byte RFC 8032 seed, not a 64-byte expanded key.
 *   Signing is deterministic, so backends must agree byte-for-byte.
 * - ed25519Verify must reject invalid signatures. Acceptance of non-canonical
 *   edge encodings may differ per backend (zip215 vs strict); that only
 *   affects adversarially crafted signatures and fails closed.
 * - xchacha20poly1305Encrypt returns ciphertext || 16-byte Poly1305 tag;
 *   decrypt must throw on authentication failure.
 * - randomBytes must be a CSPRNG. Registration rejects providers without one.
 *
 * registerCryptoPrimitives() self-tests every supplied primitive and throws
 * (leaving the previous provider active) on any mismatch: each must reproduce
 * published test vectors (RFC 7748, RFC 8032, RFC 5869, the XChaCha draft) and
 * match the built-in @noble implementation on fixed inputs at the sizes the
 * protocol uses (see selfTest). That catches a backend that is wrong on those
 * inputs; it cannot prove a backend right on every input.
 */

import { x25519, ed25519 } from "@noble/curves/ed25519.js";
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { randomBytes as nobleRandomBytes } from "@noble/ciphers/utils.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import {
  RFC5869_A1,
  RFC5869_A3,
  RFC7748_6_1,
  RFC8032_7_1_TEST1,
  XCHACHA_DRAFT03_A3_1,
} from "./known-answers.js";

/**
 * A full set of low-level primitives. All functions are synchronous and
 * operate on plain Uint8Arrays.
 */
export interface CryptoPrimitives {
  /** Cryptographically secure random bytes. */
  randomBytes(length: number): Uint8Array;
  /** X25519 public key from a clamped 32-byte scalar. */
  x25519GetPublicKey(clampedPriv32: Uint8Array): Uint8Array;
  /** X25519 shared secret (32 bytes) from a clamped scalar and a public key. */
  x25519SharedSecret(clampedPriv32: Uint8Array, pub32: Uint8Array): Uint8Array;
  /** Ed25519 public key from a 32-byte seed. */
  ed25519GetPublicKey(seed32: Uint8Array): Uint8Array;
  /** Ed25519 detached signature (64 bytes) over message with a 32-byte seed. */
  ed25519Sign(seed32: Uint8Array, message: Uint8Array): Uint8Array;
  /** Ed25519 signature verification. Returns false rather than throwing. */
  ed25519Verify(
    pub32: Uint8Array,
    message: Uint8Array,
    sig64: Uint8Array
  ): boolean;
  /** XChaCha20-Poly1305 encrypt; returns ciphertext || 16-byte tag. */
  xchacha20poly1305Encrypt(
    key32: Uint8Array,
    nonce24: Uint8Array,
    plaintext: Uint8Array,
    aad: Uint8Array
  ): Uint8Array;
  /** XChaCha20-Poly1305 decrypt; throws on authentication failure. */
  xchacha20poly1305Decrypt(
    key32: Uint8Array,
    nonce24: Uint8Array,
    ciphertext: Uint8Array,
    aad: Uint8Array
  ): Uint8Array;
  /** HKDF-SHA256 (RFC 5869). */
  hkdfSha256(
    ikm: Uint8Array,
    salt: Uint8Array,
    info: Uint8Array,
    length: number
  ): Uint8Array;
}

/**
 * A provider overrides any subset of primitives. `randomBytes` is required:
 * a backend that can't produce CSPRNG output has no business being registered.
 */
export type CryptoPrimitivesProvider = { name: string } & Partial<
  Omit<CryptoPrimitives, "randomBytes">
> &
  Pick<CryptoPrimitives, "randomBytes">;

/** Pure-JS reference implementations (@noble). Always available. */
const noblePrimitives: CryptoPrimitives = {
  randomBytes: (length) => nobleRandomBytes(length),
  x25519GetPublicKey: (priv32) => x25519.getPublicKey(priv32),
  x25519SharedSecret: (priv32, pub32) => {
    const ss = x25519.getSharedSecret(priv32, pub32);
    return ss.length === 32 ? ss : ss.slice(-32);
  },
  ed25519GetPublicKey: (seed32) => ed25519.getPublicKey(seed32),
  ed25519Sign: (seed32, message) => ed25519.sign(message, seed32),
  ed25519Verify: (pub32, message, sig64) => {
    try {
      return ed25519.verify(sig64, message, pub32);
    } catch {
      return false;
    }
  },
  xchacha20poly1305Encrypt: (key32, nonce24, plaintext, aad) =>
    xchacha20poly1305(key32, nonce24, aad).encrypt(plaintext),
  xchacha20poly1305Decrypt: (key32, nonce24, ciphertext, aad) =>
    xchacha20poly1305(key32, nonce24, aad).decrypt(ciphertext),
  hkdfSha256: (ikm, salt, info, length) => hkdf(sha256, ikm, salt, info, length),
};

let active: CryptoPrimitives = noblePrimitives;
let activeName = "noble";

/** The currently active primitives. Internal to the wrapper modules. */
export function getPrimitives(): CryptoPrimitives {
  return active;
}

/** Name of the active provider ("noble" unless one was registered). */
export function getCryptoPrimitivesProviderName(): string {
  return activeName;
}

/** Restores the built-in @noble implementations (tests / benchmarks). */
export function resetCryptoPrimitives(): void {
  active = noblePrimitives;
  activeName = "noble";
}

function eq(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return d === 0;
}

function fixedBytes(length: number, seed: number): Uint8Array {
  const out = new Uint8Array(length);
  for (let i = 0; i < length; i++) out[i] = (i * 7 + seed) & 0xff;
  return out;
}

function clamped(scalar: Uint8Array): Uint8Array {
  const k = scalar.slice();
  k[0] = (k[0] ?? 0) & 248;
  k[31] = ((k[31] ?? 0) & 127) | 64;
  return k;
}

/** True when fn returns without throwing. */
function completes(fn: () => unknown): boolean {
  try {
    fn();
  } catch {
    return false;
  }
  return true;
}

/**
 * Self-tests a provider at registration. Every supplied primitive must reproduce
 * the published constants in known-answers.ts (RFC 7748 §6.1, RFC 8032 §7.1
 * test 1, RFC 5869 A.1 with its 32-byte prefix and A.3, draft-irtf-cfrg-xchacha-03
 * A.3.1), and must match the built-in @noble implementation on fixed inputs at
 * the sizes the protocol uses: HKDF at 32 bytes with a 32-byte zero salt and 128-
 * or 160-byte input (X3DH), at 64 bytes with a 32-byte or empty salt (root and
 * chain steps); AEAD with an empty AAD, an empty plaintext, 16,500 bytes, and
 * AADs of 33 bytes (unaligned, past two Poly1305 blocks), 55 bytes (a self seal),
 * 281 bytes (AD and a pairwise header) and 299 bytes (AD and a header with a
 * group slot). Every covered primitive is deterministic, so a byte difference
 * would mean keys or ciphertext that other backends cannot read. A decrypt that
 * throws on a valid input counts as a divergence. Throws on the first
 * divergence. This catches a backend that is wrong on these inputs; it cannot
 * prove a backend right on every input. Cost is a few dozen operations, run
 * once at registration.
 */
function selfTest(p: CryptoPrimitivesProvider): void {
  const fail = (what: string): never => {
    throw new Error(
      `registerCryptoPrimitives("${p.name}"): ${what} diverges from the reference implementation; provider rejected`
    );
  };

  // CSPRNG sanity: correct type/length, and two draws must differ. This can't
  // prove randomness, but it rejects stubs returning constants/zeros.
  const r1 = p.randomBytes(32);
  const r2 = p.randomBytes(32);
  if (!(r1 instanceof Uint8Array) || r1.length !== 32 || r2.length !== 32) {
    throw new Error(
      `registerCryptoPrimitives("${p.name}"): randomBytes must return a Uint8Array of the requested length`
    );
  }
  if (eq(r1, r2) || r1.every((b) => b === 0)) {
    throw new Error(
      `registerCryptoPrimitives("${p.name}"): randomBytes output is not random; provider rejected`
    );
  }

  // X25519. Scalars reach a provider already clamped (the contract above).
  const scalarA = clamped(fixedBytes(32, 11));
  const scalarB = clamped(fixedBytes(32, 42));
  const x = RFC7748_6_1;
  if (p.x25519GetPublicKey) {
    if (
      !eq(p.x25519GetPublicKey(scalarA), noblePrimitives.x25519GetPublicKey(scalarA)) ||
      !eq(p.x25519GetPublicKey(clamped(x.alicePriv)), x.alicePub) ||
      !eq(p.x25519GetPublicKey(clamped(x.bobPriv)), x.bobPub)
    ) {
      fail("x25519GetPublicKey");
    }
  }
  if (p.x25519SharedSecret) {
    const pubB = noblePrimitives.x25519GetPublicKey(scalarB);
    if (
      !eq(
        p.x25519SharedSecret(scalarA, pubB),
        noblePrimitives.x25519SharedSecret(scalarA, pubB)
      ) ||
      !eq(p.x25519SharedSecret(clamped(x.alicePriv), x.bobPub), x.shared) ||
      !eq(p.x25519SharedSecret(clamped(x.bobPriv), x.alicePub), x.shared)
    ) {
      fail("x25519SharedSecret");
    }
  }

  // Ed25519.
  const seed = fixedBytes(32, 3);
  const msg = fixedBytes(64, 5);
  const refPub = noblePrimitives.ed25519GetPublicKey(seed);
  const refSig = noblePrimitives.ed25519Sign(seed, msg);
  const ed = RFC8032_7_1_TEST1;
  if (
    p.ed25519GetPublicKey &&
    (!eq(p.ed25519GetPublicKey(seed), refPub) || !eq(p.ed25519GetPublicKey(ed.seed), ed.pub))
  ) {
    fail("ed25519GetPublicKey");
  }
  if (
    p.ed25519Sign &&
    (!eq(p.ed25519Sign(seed, msg), refSig) || !eq(p.ed25519Sign(ed.seed, ed.message), ed.sig))
  ) {
    fail("ed25519Sign");
  }
  if (p.ed25519Verify) {
    const tampered = refSig.slice();
    tampered[0] = (tampered[0] ?? 0) ^ 1;
    if (
      !p.ed25519Verify(refPub, msg, refSig) ||
      p.ed25519Verify(refPub, msg, tampered) ||
      !p.ed25519Verify(ed.pub, ed.message, ed.sig)
    ) {
      fail("ed25519Verify");
    }
  }

  // XChaCha20-Poly1305: the published vector, then fixed inputs at the edges.
  const key = fixedBytes(32, 9);
  const nonce = fixedBytes(24, 13);
  const aad = fixedBytes(16, 17);
  const aeadCases: Array<{ label: string; key: Uint8Array; nonce: Uint8Array; pt: Uint8Array; aad: Uint8Array }> = [
    { label: "", key, nonce, pt: fixedBytes(100, 21), aad },
    { label: " (empty AAD)", key, nonce, pt: fixedBytes(100, 23), aad: new Uint8Array(0) },
    { label: " (empty plaintext)", key, nonce, pt: new Uint8Array(0), aad },
    { label: " (16,500-byte plaintext)", key, nonce, pt: fixedBytes(16_500, 27), aad },
    // The AAD sizes the protocol uses. AD is 164 bytes; a pairwise header H
    // with small counters is 117 bytes, and 135 with a group slot; a self
    // seal's AAD is 55 bytes. 33 bytes is unaligned and runs one byte past
    // two Poly1305 blocks, so a backend that drops AAD past 32 bytes fails here.
    { label: " (33-byte AAD)", key, nonce, pt: fixedBytes(100, 37), aad: fixedBytes(33, 39) },
    { label: " (55-byte AAD, self seal)", key, nonce, pt: fixedBytes(100, 41), aad: fixedBytes(55, 43) },
    { label: " (281-byte AAD, AD and a pairwise header)", key, nonce, pt: fixedBytes(100, 45), aad: fixedBytes(281, 47) },
    { label: " (299-byte AAD, AD and a group header)", key, nonce, pt: fixedBytes(100, 49), aad: fixedBytes(299, 51) },
  ];
  const xc = XCHACHA_DRAFT03_A3_1;
  if (p.xchacha20poly1305Encrypt) {
    if (!eq(p.xchacha20poly1305Encrypt(xc.key, xc.nonce, xc.plaintext, xc.aad), xc.sealed)) {
      fail("xchacha20poly1305Encrypt (draft-irtf-cfrg-xchacha-03 A.3.1)");
    }
    for (const c of aeadCases) {
      const ref = noblePrimitives.xchacha20poly1305Encrypt(c.key, c.nonce, c.pt, c.aad);
      if (!eq(p.xchacha20poly1305Encrypt(c.key, c.nonce, c.pt, c.aad), ref)) {
        fail(`xchacha20poly1305Encrypt${c.label}`);
      }
    }
  }
  if (p.xchacha20poly1305Decrypt) {
    // A throw on a valid input is a divergence, reported like any other.
    const opens = (k: Uint8Array, n: Uint8Array, ct: Uint8Array, ad: Uint8Array, pt: Uint8Array): boolean => {
      try {
        return eq(p.xchacha20poly1305Decrypt!(k, n, ct, ad), pt);
      } catch {
        return false;
      }
    };
    if (!opens(xc.key, xc.nonce, xc.sealed, xc.aad, xc.plaintext)) {
      fail("xchacha20poly1305Decrypt (draft-irtf-cfrg-xchacha-03 A.3.1)");
    }
    for (const c of aeadCases) {
      const ref = noblePrimitives.xchacha20poly1305Encrypt(c.key, c.nonce, c.pt, c.aad);
      if (!opens(c.key, c.nonce, ref, c.aad, c.pt)) {
        fail(`xchacha20poly1305Decrypt${c.label}`);
      }
    }
    const tamperedCt = noblePrimitives.xchacha20poly1305Encrypt(key, nonce, fixedBytes(100, 21), aad);
    tamperedCt[0] = (tamperedCt[0] ?? 0) ^ 1;
    if (completes(() => p.xchacha20poly1305Decrypt!(key, nonce, tamperedCt, aad))) {
      fail("xchacha20poly1305Decrypt (auth failure must throw)");
    }
  }

  // HKDF-SHA256: the published vectors, then the protocol's shapes.
  if (p.hkdfSha256) {
    const a1 = RFC5869_A1;
    const a3 = RFC5869_A3;
    if (
      !eq(p.hkdfSha256(a1.ikm, a1.salt, a1.info, a1.okm.length), a1.okm) ||
      !eq(p.hkdfSha256(a1.ikm, a1.salt, a1.info, 32), a1.okm.subarray(0, 32)) ||
      !eq(p.hkdfSha256(a3.ikm, a3.salt, a3.info, a3.okm.length), a3.okm)
    ) {
      fail("hkdfSha256 (RFC 5869)");
    }
    const info = fixedBytes(11, 31);
    const zeroSalt = new Uint8Array(32);
    const hkdfCases: Array<[string, Uint8Array, Uint8Array, number]> = [
      ["length 64", fixedBytes(32, 25), fixedBytes(32, 29), 64],
      ["length 64, empty salt", fixedBytes(32, 25), new Uint8Array(0), 64],
      ["length 32, 128-byte input", fixedBytes(128, 33), zeroSalt, 32],
      ["length 32, 160-byte input", fixedBytes(160, 35), zeroSalt, 32],
    ];
    for (const [label, ikm, salt, length] of hkdfCases) {
      if (!eq(p.hkdfSha256(ikm, salt, info, length), noblePrimitives.hkdfSha256(ikm, salt, info, length))) {
        fail(`hkdfSha256 (${label})`);
      }
    }
  }
}

/**
 * Registers a primitives provider. Unsupplied primitives keep the built-in
 * @noble implementations. Must be called before any other moretag-crypto use
 * (registering later is safe for correctness — all backends interop — but
 * anything already derived was simply computed on the slow path).
 *
 * @throws if the provider lacks a working CSPRNG or any supplied primitive
 *   fails the known-answer self-test. The previous provider stays active.
 */
export function registerCryptoPrimitives(
  provider: CryptoPrimitivesProvider
): void {
  if (typeof provider.randomBytes !== "function") {
    throw new Error(
      `registerCryptoPrimitives("${provider.name}"): provider must supply a CSPRNG randomBytes`
    );
  }
  selfTest(provider);
  const { name, ...overrides } = provider;
  active = { ...noblePrimitives, ...overrides };
  activeName = name;
}

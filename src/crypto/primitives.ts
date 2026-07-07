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
 * registerCryptoPrimitives() runs known-answer self-tests on every supplied
 * primitive against the built-in reference implementation and throws (leaving
 * the previous provider active) on any mismatch, so a subtly incompatible
 * native implementation can never silently corrupt sessions or stored data.
 */

import { x25519, ed25519 } from "@noble/curves/ed25519.js";
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { randomBytes as nobleRandomBytes } from "@noble/ciphers/utils.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";

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

/**
 * Self-tests a provider against the built-in reference implementation on
 * fixed inputs. Throws with a descriptive message on the first divergence.
 * All covered primitives are deterministic, so any byte difference here would
 * mean cross-platform ciphertext/key divergence — i.e. unrecoverable message
 * loss once one-time ratchet keys are involved. Cost is a handful of
 * operations, run once at registration.
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

  // Clamped fixed scalar (matches what the wrappers pass at runtime).
  const scalarA = fixedBytes(32, 11);
  scalarA[0] = (scalarA[0] ?? 0) & 248;
  scalarA[31] = ((scalarA[31] ?? 0) & 127) | 64;
  const scalarB = fixedBytes(32, 42);
  scalarB[0] = (scalarB[0] ?? 0) & 248;
  scalarB[31] = ((scalarB[31] ?? 0) & 127) | 64;

  if (p.x25519GetPublicKey) {
    if (
      !eq(p.x25519GetPublicKey(scalarA), noblePrimitives.x25519GetPublicKey(scalarA))
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
      )
    ) {
      fail("x25519SharedSecret");
    }
  }

  const seed = fixedBytes(32, 3);
  const msg = fixedBytes(64, 5);
  const refPub = noblePrimitives.ed25519GetPublicKey(seed);
  const refSig = noblePrimitives.ed25519Sign(seed, msg);
  if (p.ed25519GetPublicKey && !eq(p.ed25519GetPublicKey(seed), refPub)) {
    fail("ed25519GetPublicKey");
  }
  if (p.ed25519Sign && !eq(p.ed25519Sign(seed, msg), refSig)) {
    fail("ed25519Sign");
  }
  if (p.ed25519Verify) {
    const tampered = refSig.slice();
    tampered[0] = (tampered[0] ?? 0) ^ 1;
    if (
      !p.ed25519Verify(refPub, msg, refSig) ||
      p.ed25519Verify(refPub, msg, tampered)
    ) {
      fail("ed25519Verify");
    }
  }

  const key = fixedBytes(32, 9);
  const nonce = fixedBytes(24, 13);
  const aad = fixedBytes(16, 17);
  const pt = fixedBytes(100, 21);
  const refCt = noblePrimitives.xchacha20poly1305Encrypt(key, nonce, pt, aad);
  if (p.xchacha20poly1305Encrypt) {
    if (!eq(p.xchacha20poly1305Encrypt(key, nonce, pt, aad), refCt)) {
      fail("xchacha20poly1305Encrypt");
    }
  }
  if (p.xchacha20poly1305Decrypt) {
    if (!eq(p.xchacha20poly1305Decrypt(key, nonce, refCt, aad), pt)) {
      fail("xchacha20poly1305Decrypt");
    }
    const tamperedCt = refCt.slice();
    tamperedCt[0] = (tamperedCt[0] ?? 0) ^ 1;
    let threw = false;
    try {
      p.xchacha20poly1305Decrypt(key, nonce, tamperedCt, aad);
    } catch {
      threw = true;
    }
    if (!threw) fail("xchacha20poly1305Decrypt (auth failure must throw)");
  }

  if (p.hkdfSha256) {
    const ikm = fixedBytes(32, 25);
    const salt = fixedBytes(32, 29);
    const info = fixedBytes(11, 31);
    if (
      !eq(
        p.hkdfSha256(ikm, salt, info, 64),
        noblePrimitives.hkdfSha256(ikm, salt, info, 64)
      ) ||
      !eq(
        p.hkdfSha256(ikm, new Uint8Array(0), info, 64),
        noblePrimitives.hkdfSha256(ikm, new Uint8Array(0), info, 64)
      )
    ) {
      fail("hkdfSha256");
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

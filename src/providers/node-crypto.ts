/**
 * CryptoPrimitivesProvider adapter for Node-crypto-shaped backends.
 *
 * Works with anything exposing the synchronous Node `crypto` API surface:
 * `node:crypto` itself (used by our cross-implementation interop tests) and
 * `react-native-quick-crypto` (JSI/BoringSSL — the fast path on Hermes, where
 * pure-JS crypto is 10-50x slower than a JIT VM). The backend is passed in by
 * the host, so this module adds no dependency to moretag-crypto.
 *
 * XChaCha20-Poly1305 is not part of the Node cipher list, so it is built the
 * standard way (draft-irtf-cfrg-xchacha): an HChaCha20 subkey derived from the
 * first 16 nonce bytes, then native ChaCha20-Poly1305 with a 12-byte nonce of
 * 4 zero bytes || the last 8 nonce bytes. HChaCha20 is a single pure-JS block
 * (negligible next to the bulk cipher) and the output is byte-identical to
 * @noble's xchacha20poly1305 — enforced by the registration self-test.
 */

import { hchacha } from "@noble/ciphers/chacha.js";
import type { CryptoPrimitivesProvider } from "../crypto/primitives.js";

/** DER prefixes for RFC 8410 raw-key import/export (fixed 32-byte keys). */
const PKCS8_X25519 = hex("302e020100300506032b656e04220420");
const SPKI_X25519 = hex("302a300506032b656e032100");
const PKCS8_ED25519 = hex("302e020100300506032b657004220420");
const SPKI_ED25519 = hex("302a300506032b6570032100");

function hex(s: string): Uint8Array {
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  let len = 0;
  for (const part of parts) len += part.length;
  const out = new Uint8Array(len);
  let off = 0;
  for (const part of parts) {
    out.set(part, off);
    off += part.length;
  }
  return out;
}

/** Copies backend output (Buffer/ArrayBuffer/TypedArray) to a plain Uint8Array. */
function toBytes(value: ArrayBuffer | Uint8Array): Uint8Array {
  if (value instanceof Uint8Array) return Uint8Array.from(value);
  return new Uint8Array(value.slice(0));
}

interface KeyObjectLike {
  export(options: { format: "der"; type: "spki" }): ArrayBuffer | Uint8Array;
}

interface CipherLike {
  setAAD(aad: Uint8Array, options?: { plaintextLength: number }): unknown;
  update(data: Uint8Array): Uint8Array;
  final(): Uint8Array;
  getAuthTag(): Uint8Array;
}

interface DecipherLike {
  setAAD(aad: Uint8Array, options?: { plaintextLength: number }): unknown;
  setAuthTag(tag: Uint8Array): unknown;
  update(data: Uint8Array): Uint8Array;
  final(): Uint8Array;
}

/**
 * The subset of the Node `crypto` module surface this adapter needs. Both
 * `node:crypto` and `react-native-quick-crypto`'s default export satisfy it.
 */
export interface NodeCryptoLike {
  randomBytes(size: number): Uint8Array;
  createPrivateKey(key: {
    key: Uint8Array;
    format: "der";
    type: "pkcs8";
  }): unknown;
  createPublicKey(
    key: unknown | { key: Uint8Array; format: "der"; type: "spki" }
  ): KeyObjectLike;
  diffieHellman(options: {
    privateKey: unknown;
    publicKey: unknown;
  }): Uint8Array;
  sign(algorithm: null | undefined, data: Uint8Array, key: unknown): Uint8Array;
  verify(
    algorithm: null | undefined,
    data: Uint8Array,
    key: unknown,
    signature: Uint8Array
  ): boolean;
  createCipheriv(
    algorithm: string,
    key: Uint8Array,
    iv: Uint8Array,
    options: { authTagLength: number }
  ): CipherLike;
  createDecipheriv(
    algorithm: string,
    key: Uint8Array,
    iv: Uint8Array,
    options: { authTagLength: number }
  ): DecipherLike;
  hkdfSync(
    digest: string,
    ikm: Uint8Array,
    salt: Uint8Array,
    info: Uint8Array,
    keylen: number
  ): ArrayBuffer | Uint8Array;
}

const CHACHA_SIGMA = u32(new TextEncoder().encode("expand 32-byte k"));

function u32(bytes: Uint8Array): Uint32Array {
  return new Uint32Array(
    bytes.buffer,
    bytes.byteOffset,
    bytes.byteLength >>> 2
  );
}

/**
 * XChaCha nonce extension: HChaCha20(key, nonce24[0..16]) -> subkey, and a
 * 12-byte ChaCha20-Poly1305 nonce of 4 zero bytes || nonce24[16..24].
 */
function xchachaSubkeyNonce(
  key32: Uint8Array,
  nonce24: Uint8Array
): { subkey: Uint8Array; nonce12: Uint8Array } {
  const out = new Uint32Array(8);
  hchacha(CHACHA_SIGMA, u32(key32.slice()), u32(nonce24.slice(0, 16)), out);
  const subkey = new Uint8Array(out.buffer, 0, 32);
  const nonce12 = new Uint8Array(12);
  nonce12.set(nonce24.subarray(16), 4);
  return { subkey, nonce12 };
}

const TAG_LENGTH = 16;

/**
 * Builds a full primitives provider from a Node-crypto-shaped backend.
 * Register the result with registerCryptoPrimitives(), which self-tests every
 * primitive against the pure-JS reference before activating it.
 */
export function createNodeCryptoPrimitives(
  backend: NodeCryptoLike,
  options: { name: string }
): CryptoPrimitivesProvider {
  const x25519Private = (priv32: Uint8Array) =>
    backend.createPrivateKey({
      key: concat(PKCS8_X25519, priv32),
      format: "der",
      type: "pkcs8",
    });

  const rawPublicFromKey = (keyObj: KeyObjectLike): Uint8Array => {
    const spki = toBytes(keyObj.export({ format: "der", type: "spki" }));
    // Raw key is the last 32 bytes of the fixed-layout RFC 8410 SPKI.
    return spki.slice(spki.length - 32);
  };

  return {
    name: options.name,

    randomBytes: (length) => toBytes(backend.randomBytes(length)),

    x25519GetPublicKey: (clampedPriv32) =>
      rawPublicFromKey(backend.createPublicKey(x25519Private(clampedPriv32))),

    x25519SharedSecret: (clampedPriv32, pub32) =>
      toBytes(
        backend.diffieHellman({
          privateKey: x25519Private(clampedPriv32),
          publicKey: backend.createPublicKey({
            key: concat(SPKI_X25519, pub32),
            format: "der",
            type: "spki",
          }),
        })
      ),

    ed25519GetPublicKey: (seed32) =>
      rawPublicFromKey(
        backend.createPublicKey(
          backend.createPrivateKey({
            key: concat(PKCS8_ED25519, seed32),
            format: "der",
            type: "pkcs8",
          })
        )
      ),

    ed25519Sign: (seed32, message) =>
      toBytes(
        backend.sign(
          null,
          message,
          backend.createPrivateKey({
            key: concat(PKCS8_ED25519, seed32),
            format: "der",
            type: "pkcs8",
          })
        )
      ),

    ed25519Verify: (pub32, message, sig64) => {
      try {
        return backend.verify(
          null,
          message,
          backend.createPublicKey({
            key: concat(SPKI_ED25519, pub32),
            format: "der",
            type: "spki",
          }),
          sig64
        );
      } catch {
        return false;
      }
    },

    xchacha20poly1305Encrypt: (key32, nonce24, plaintext, aad) => {
      const { subkey, nonce12 } = xchachaSubkeyNonce(key32, nonce24);
      const cipher = backend.createCipheriv("chacha20-poly1305", subkey, nonce12, {
        authTagLength: TAG_LENGTH,
      });
      cipher.setAAD(aad, { plaintextLength: plaintext.length });
      return concat(
        toBytes(cipher.update(plaintext)),
        toBytes(cipher.final()),
        toBytes(cipher.getAuthTag())
      );
    },

    xchacha20poly1305Decrypt: (key32, nonce24, ciphertext, aad) => {
      if (ciphertext.length < TAG_LENGTH) {
        throw new Error("xchacha20poly1305: ciphertext shorter than tag");
      }
      const { subkey, nonce12 } = xchachaSubkeyNonce(key32, nonce24);
      const decipher = backend.createDecipheriv(
        "chacha20-poly1305",
        subkey,
        nonce12,
        { authTagLength: TAG_LENGTH }
      );
      const body = ciphertext.subarray(0, ciphertext.length - TAG_LENGTH);
      decipher.setAAD(aad, { plaintextLength: body.length });
      decipher.setAuthTag(ciphertext.subarray(ciphertext.length - TAG_LENGTH));
      // final() throws on Poly1305 tag mismatch — required by the contract.
      return concat(toBytes(decipher.update(body)), toBytes(decipher.final()));
    },

    hkdfSha256: (ikm, salt, info, length) =>
      toBytes(backend.hkdfSync("sha256", ikm, salt, info, length)),
  };
}

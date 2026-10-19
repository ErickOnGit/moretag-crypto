/**
 * Cross-implementation interop tests.
 *
 * Drives the node-crypto adapter with node:crypto (OpenSSL) and checks every
 * primitive against @noble, both as raw known-answer comparisons and as full
 * round-trips (encrypt/sign on one implementation, decrypt/verify on the
 * other). OpenSSL here is the same family as react-native-quick-crypto's
 * BoringSSL, so a divergence in x25519 clamping, zero-shared-secret handling,
 * ed25519 rules, the XChaCha nonce-extension construction, or HKDF would
 * surface in this suite before it could ever corrupt a live ratchet.
 */
import { describe, it, expect, afterEach } from "vitest";
import * as nodeCrypto from "node:crypto";
import { randomBytes } from "@noble/ciphers/utils.js";
import { createNodeCryptoPrimitives, type NodeCryptoLike } from "./node-crypto.js";
import {
  registerCryptoPrimitives,
  resetCryptoPrimitives,
  getPrimitives,
  getCryptoPrimitivesProviderName,
} from "../crypto/primitives.js";
import {
  generateX25519Keypair,
  x25519PublicFromPrivate,
  x25519SharedSecret,
} from "../crypto/x25519.js";
import { generateEd25519Keypair, ed25519Sign, ed25519Verify } from "../crypto/ed25519.js";
import {
  aeadEncryptXChaCha20Poly1305,
  aeadDecryptXChaCha20Poly1305,
} from "../crypto/aead.js";
import { hkdfSha256 } from "../crypto/hkdf.js";
import { x3dhInitiatorV1, x3dhResponderV1, buildSpkSigMessage } from "../crypto/x3dh.js";
import { bytesToBase64 } from "../encoding/base64.js";
import { ratchetInit, ratchetEncrypt, ratchetDecrypt } from "../ratchet/ratchet.js";
import type { X3DHPrekeyBundleV1 } from "../wire/x3dh.js";

const noble = getPrimitives(); // module load runs before any registration
const provider = createNodeCryptoPrimitives(nodeCrypto as unknown as NodeCryptoLike, {
  name: "node:crypto",
});

const registerNode = () => registerCryptoPrimitives(provider);
const ITERATIONS = 25;

afterEach(() => {
  resetCryptoPrimitives();
});

describe("node-crypto adapter registration", () => {
  it("passes the registration self-test", () => {
    registerNode();
    expect(getCryptoPrimitivesProviderName()).toBe("node:crypto");
  });
});

describe("primitive-level interop (openssl vs noble)", () => {
  it("x25519: identical public keys and shared secrets for random scalars", () => {
    for (let i = 0; i < ITERATIONS; i++) {
      const a = randomBytes(32);
      const b = randomBytes(32);
      // Wrapper clamps; compare through the public wrapper on both providers.
      resetCryptoPrimitives();
      const pubANoble = x25519PublicFromPrivate(a);
      const pubBNoble = x25519PublicFromPrivate(b);
      const ssNoble = x25519SharedSecret(a, pubBNoble);

      registerNode();
      expect(x25519PublicFromPrivate(a)).toEqual(pubANoble);
      expect(x25519SharedSecret(a, pubBNoble)).toEqual(ssNoble);
      // and the reverse direction agrees (DH symmetry across implementations)
      expect(x25519SharedSecret(b, pubANoble)).toEqual(ssNoble);
    }
  });

  it("x25519: unclamped scalars (high bit set / low bits set) still agree", () => {
    const edge = randomBytes(32);
    edge[0] = 0xff;
    edge[31] = 0xff; // clamping must normalize identically on both sides
    resetCryptoPrimitives();
    const pubNoble = x25519PublicFromPrivate(edge);
    registerNode();
    expect(x25519PublicFromPrivate(edge)).toEqual(pubNoble);
  });

  it("x25519: both implementations reject the all-zero shared secret", () => {
    const priv = randomBytes(32);
    const lowOrderPub = new Uint8Array(32); // point of order 1 -> zero output
    resetCryptoPrimitives();
    expect(() => x25519SharedSecret(priv, lowOrderPub)).toThrow();
    registerNode();
    expect(() => x25519SharedSecret(priv, lowOrderPub)).toThrow();
  });

  it("ed25519: identical pubs and byte-identical deterministic signatures", () => {
    for (let i = 0; i < ITERATIONS; i++) {
      const seed = randomBytes(32);
      const msg = randomBytes(1 + Math.floor(Math.random() * 512));
      expect(provider.ed25519GetPublicKey!(seed)).toEqual(
        noble.ed25519GetPublicKey(seed)
      );
      expect(provider.ed25519Sign!(seed, msg)).toEqual(noble.ed25519Sign(seed, msg));
    }
  });

  it("ed25519: signatures cross-verify and tampering fails on both", () => {
    const seed = randomBytes(32);
    const pub = noble.ed25519GetPublicKey(seed);
    const msg = randomBytes(200);
    const sigNoble = noble.ed25519Sign(seed, msg);
    const sigNode = provider.ed25519Sign!(seed, msg);

    expect(provider.ed25519Verify!(pub, msg, sigNoble)).toBe(true);
    expect(noble.ed25519Verify(pub, msg, sigNode)).toBe(true);

    const bad = sigNoble.slice();
    bad[10] = (bad[10] ?? 0) ^ 0x40;
    expect(provider.ed25519Verify!(pub, msg, bad)).toBe(false);
    expect(noble.ed25519Verify(pub, msg, bad)).toBe(false);
  });

  it("xchacha20poly1305: byte-identical ciphertext and cross round-trips", () => {
    for (let i = 0; i < ITERATIONS; i++) {
      const key = randomBytes(32);
      const nonce = randomBytes(24);
      const aad = randomBytes(Math.floor(Math.random() * 64));
      const pt = randomBytes(Math.floor(Math.random() * 2048));

      const ctNoble = noble.xchacha20poly1305Encrypt(key, nonce, pt, aad);
      const ctNode = provider.xchacha20poly1305Encrypt!(key, nonce, pt, aad);
      expect(ctNode).toEqual(ctNoble);

      expect(provider.xchacha20poly1305Decrypt!(key, nonce, ctNoble, aad)).toEqual(pt);
      expect(noble.xchacha20poly1305Decrypt(key, nonce, ctNode, aad)).toEqual(pt);
    }
  });

  it("xchacha20poly1305: empty plaintext and empty AAD interop", () => {
    const key = randomBytes(32);
    const nonce = randomBytes(24);
    const empty = new Uint8Array(0);
    const ctNoble = noble.xchacha20poly1305Encrypt(key, nonce, empty, empty);
    expect(provider.xchacha20poly1305Encrypt!(key, nonce, empty, empty)).toEqual(
      ctNoble
    );
    expect(provider.xchacha20poly1305Decrypt!(key, nonce, ctNoble, empty)).toEqual(
      empty
    );
  });

  it("xchacha20poly1305: node adapter rejects tampered ciphertext and AAD", () => {
    const key = randomBytes(32);
    const nonce = randomBytes(24);
    const aad = randomBytes(13);
    const ct = noble.xchacha20poly1305Encrypt(key, nonce, randomBytes(64), aad);
    const tampered = ct.slice();
    tampered[3] = (tampered[3] ?? 0) ^ 1;
    expect(() =>
      provider.xchacha20poly1305Decrypt!(key, nonce, tampered, aad)
    ).toThrow();
    const wrongAad = aad.slice();
    wrongAad[0] = (wrongAad[0] ?? 0) ^ 1;
    expect(() =>
      provider.xchacha20poly1305Decrypt!(key, nonce, ct, wrongAad)
    ).toThrow();
  });

  it("hkdf-sha256: identical output including empty salt (chain-key KDF shape)", () => {
    for (const saltLen of [0, 32]) {
      const ikm = randomBytes(32);
      const salt = randomBytes(saltLen);
      const info = new TextEncoder().encode("moretag/v1/ckmk");
      expect(provider.hkdfSha256!(ikm, salt, info, 64)).toEqual(
        noble.hkdfSha256(ikm, salt, info, 64)
      );
    }
  });
});

describe("protocol-level interop: messages encrypted natively decrypt on noble and vice versa", () => {
  function freshBundleAndKeys() {
    // Build a minimal self-signed prekey bundle (fork-flat shape).
    const ik = generateX25519Keypair();
    const ikSig = generateEd25519Keypair();
    const spk = generateX25519Keypair();
    const sigMsg = buildSpkSigMessage({
      recipient_device_id: "device-b",
      ik_pub32: ik.pub32,
      spk_pub32: spk.pub32,
      spk_id: 1,
    });
    const bundle: X3DHPrekeyBundleV1 = {
      v: 1,
      alg: "x3dh-x25519-hkdf-sha256+ed25519",
      recipient_device_id: "device-b",
      ik_pub_b64: bytesToBase64(ik.pub32),
      ik_sig_pub_b64: bytesToBase64(ikSig.pub32),
      spk_id: 1,
      spk_pub_b64: bytesToBase64(spk.pub32),
      spk_sig_b64: bytesToBase64(ed25519Sign(ikSig.priv32, sigMsg)),
    };
    return { ik, spk, bundle };
  }

  function runConversation(encryptOn: "node" | "noble", decryptOn: "node" | "noble") {
    const use = (which: "node" | "noble") =>
      which === "node" ? registerNode() : resetCryptoPrimitives();

    // X3DH on the encrypting side
    use(encryptOn);
    const { ik, spk, bundle } = freshBundleAndKeys();
    const initiatorIk = generateX25519Keypair();
    const { session_init, rk32: rkA } = x3dhInitiatorV1({
      sender_device_id: "device-a",
      recipient_bundle: bundle,
      initiator_ik_priv32: initiatorIk.priv32,
    });

    let alice = ratchetInit({
      rk32: rkA,
      remoteDhPub32: spk.pub32,
      sendingFirst: true,
    });
    const aliceInitialDhPub32 = alice.dh_self.pub32;

    const sent: { header: any; ciphertext_b64: string; plaintext: Uint8Array }[] = [];
    for (let i = 0; i < 10; i++) {
      const plaintext = new TextEncoder().encode(`msg ${i} ` + "x".repeat(i * 20));
      const res = ratchetEncrypt({
        state: alice,
        plaintext,
        sender_device_id: "device-a",
        recipient_device_id: "device-b",
      });
      alice = res.state;
      sent.push({ header: res.header, ciphertext_b64: res.ciphertext_b64, plaintext });
    }

    // X3DH + decryption on the other implementation
    use(decryptOn);
    const { rk32: rkB } = x3dhResponderV1({
      session_init,
      recipient_ik_priv32: ik.priv32,
      recipient_spk_priv32: spk.priv32,
    });
    expect(rkB).toEqual(rkA); // root keys agree across implementations

    let bob = ratchetInit({
      rk32: rkB,
      selfDh: spk,
      remoteDhPub32: aliceInitialDhPub32,
      sendingFirst: false,
    });
    for (const m of sent) {
      const res = ratchetDecrypt({
        state: bob,
        header: m.header,
        ciphertext_b64: m.ciphertext_b64,
      });
      bob = res.state;
      expect(res.plaintext).toEqual(m.plaintext);
    }
  }

  it("encrypt on node:crypto → decrypt on noble", () => {
    runConversation("node", "noble");
  });

  it("encrypt on noble → decrypt on node:crypto", () => {
    runConversation("noble", "node");
  });
});

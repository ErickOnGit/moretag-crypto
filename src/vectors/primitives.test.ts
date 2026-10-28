/**
 * vectors/primitives.json (published RFC and draft vectors, copied by hand, and
 * marked derived entries) against @noble and node:crypto through the library's
 * wrappers.
 */
import { describe, it, expect, afterEach } from "vitest";
import { createHash } from "node:crypto";
import { hchacha } from "@noble/ciphers/chacha.js";
import { hex, loadVector, PROVIDERS, resetProviders, scriptedRandomness, thrownBy, unhex } from "./support.js";
import { x25519PublicFromPrivate, x25519SharedSecret } from "../crypto/x25519.js";
import { ed25519Sign, ed25519Verify } from "../crypto/ed25519.js";
import { getPrimitives } from "../crypto/primitives.js";
import { hkdfSha256 } from "../crypto/hkdf.js";
import { aeadDecryptXChaCha20Poly1305, aeadEncryptXChaCha20Poly1305 } from "../crypto/aead.js";
import { LowOrderKeyError } from "../errors.js";

const file = loadVector("primitives.json");

afterEach(() => resetProviders());

it("HChaCha20, draft-irtf-cfrg-xchacha-03 §2.2.1 (@noble, the function both providers use)", () => {
  const v = file.hchacha20.draft_xchacha_03_2_2_1;
  const u32 = (b: Uint8Array) => new Uint32Array(b.buffer, b.byteOffset, b.byteLength >>> 2);
  const out = new Uint32Array(8);
  hchacha(u32(new TextEncoder().encode("expand 32-byte k")), u32(unhex(v.key)), u32(unhex(v.nonce)), out);
  expect(hex(new Uint8Array(out.buffer))).toBe(v.output);
});

describe.each(PROVIDERS.map((p) => p.name))("primitives.json on %s", (providerName) => {
  it("X25519: RFC 7748 §5.2 vectors, the iterated results after 1 and 1,000 rounds, §6.1", () => {
    scriptedRandomness(providerName);
    const x = file.x25519;
    for (const name of ["rfc7748_5_2_vector_1", "rfc7748_5_2_vector_2"]) {
      expect(hex(x25519SharedSecret(unhex(x[name].scalar), unhex(x[name].u))), name).toBe(x[name].output);
    }
    let k: Uint8Array = unhex(x.rfc7748_5_2_iterated.start);
    let u: Uint8Array = k.slice();
    for (let i = 1; i <= 1000; i++) {
      [k, u] = [x25519SharedSecret(k, u), k];
      if (i === 1) expect(hex(k)).toBe(x.rfc7748_5_2_iterated.after_1);
    }
    expect(hex(k)).toBe(x.rfc7748_5_2_iterated.after_1000);
    const d = x.rfc7748_6_1;
    expect(hex(x25519PublicFromPrivate(unhex(d.alice_private)))).toBe(d.alice_public);
    expect(hex(x25519PublicFromPrivate(unhex(d.bob_private)))).toBe(d.bob_public);
    expect(hex(x25519SharedSecret(unhex(d.alice_private), unhex(d.bob_public)))).toBe(d.shared);
    expect(hex(x25519SharedSecret(unhex(d.bob_private), unhex(d.alice_public)))).toBe(d.shared);
  });

  it("X25519: the seven derived low-order u values are refused with low_order_key", () => {
    scriptedRandomness(providerName);
    const x = file.x25519;
    expect(x.derived_low_order_refused.values).toHaveLength(7);
    for (const { name, u } of x.derived_low_order_refused.values) {
      for (const scalar of [x.rfc7748_5_2_vector_1.scalar, x.rfc7748_6_1.alice_private]) {
        expect(thrownBy(() => x25519SharedSecret(unhex(scalar), unhex(u))), name).toBeInstanceOf(LowOrderKeyError);
      }
    }
  });

  it("Ed25519: RFC 8032 §7.1 tests 1 to 3, and test 1 with S + L refused", () => {
    scriptedRandomness(providerName);
    const e = file.ed25519;
    for (const name of ["rfc8032_7_1_test_1", "rfc8032_7_1_test_2", "rfc8032_7_1_test_3"]) {
      const v = e[name];
      expect(hex(getPrimitives().ed25519GetPublicKey(unhex(v.secret_key))), name).toBe(v.public_key);
      expect(hex(ed25519Sign(unhex(v.secret_key), unhex(v.message))), name).toBe(v.signature);
      expect(ed25519Verify(unhex(v.public_key), unhex(v.message), unhex(v.signature)), name).toBe(true);
    }
    const s = e.derived_test_1_s_plus_l_refused;
    expect(s.valid).toBe(false);
    expect(ed25519Verify(unhex(s.public_key), unhex(s.message), unhex(s.signature))).toBe(false);
  });

  it("HKDF-SHA256: RFC 5869 A.1 to A.3, the 32-byte prefix and the empty salt equal to 32 zero bytes", () => {
    scriptedRandomness(providerName);
    for (const [name, v] of Object.entries<any>(file.hkdf_sha256)) {
      expect(hex(hkdfSha256(unhex(v.ikm), unhex(v.salt), unhex(v.info), v.length)), name).toBe(v.okm);
    }
    const a3 = file.hkdf_sha256.rfc5869_a_3;
    expect(hex(hkdfSha256(unhex(a3.ikm), new Uint8Array(32), unhex(a3.info), a3.length))).toBe(a3.okm);
  });

  it("XChaCha20-Poly1305: draft-irtf-cfrg-xchacha-03 A.3.1", () => {
    scriptedRandomness(providerName);
    const v = file.xchacha20poly1305.draft_xchacha_03_a_3_1;
    const sealed = unhex(v.ciphertext + v.tag);
    const pt = aeadDecryptXChaCha20Poly1305(unhex(v.key), unhex(v.nonce), sealed, unhex(v.aad));
    expect(pt.length).toBe(v.plaintext_length);
    expect(createHash("sha256").update(pt).digest("hex")).toBe(v.plaintext_sha256);
    expect(hex(aeadEncryptXChaCha20Poly1305(unhex(v.key), unhex(v.nonce), pt, unhex(v.aad)))).toBe(v.ciphertext + v.tag);
  });
});

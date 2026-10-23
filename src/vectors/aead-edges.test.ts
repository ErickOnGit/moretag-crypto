/**
 * vectors/aead-edges.json: XChaCha20-Poly1305 at the edge lengths, once per
 * provider, and one sealLocalV2 case with its nonce draw scripted.
 */
import { describe, it, expect, afterEach } from "vitest";
import { hchacha } from "@noble/ciphers/chacha.js";
import { hex, hexToB64, loadVector, PROVIDERS, resetProviders, scriptedRandomness, unhex } from "./support.js";
import { aeadDecryptXChaCha20Poly1305, aeadEncryptXChaCha20Poly1305 } from "../crypto/aead.js";
import { buildSelfSealAadV2, openLocalV2, sealLocalV2 } from "../crypto/seal.js";

const file = loadVector("aead-edges.json");

afterEach(() => resetProviders());

const u32 = (b: Uint8Array) => new Uint32Array(b.buffer, b.byteOffset, b.byteLength >>> 2);

it("the HChaCha20 subkey of every case matches draft-irtf-cfrg-xchacha-03 §2.3", () => {
  const sigma = u32(new TextEncoder().encode("expand 32-byte k"));
  for (const c of file.cases) {
    const out = new Uint32Array(8);
    hchacha(sigma, u32(unhex(c.key_hex)), u32(unhex(c.nonce_hex).slice(0, 16)), out);
    expect(hex(new Uint8Array(out.buffer)), c.name).toBe(c.hchacha20_subkey_hex);
    expect(c.chacha20_nonce12_hex).toBe("00000000" + c.nonce_hex.slice(32));
  }
});

describe.each(PROVIDERS.map((p) => p.name))("aead-edges.json on %s", (providerName) => {
  it("every plaintext and AAD length seals and opens to the listed bytes", () => {
    scriptedRandomness(providerName);
    expect(file.cases.length).toBeGreaterThan(30);
    for (const c of file.cases) {
      const key = unhex(c.key_hex);
      const nonce = unhex(c.nonce_hex);
      const aad = unhex(c.aad_hex);
      const pt = unhex(c.plaintext_hex);
      expect(pt.length).toBe(c.plaintext_length);
      expect(aad.length).toBe(c.aad_length);
      const sealed = aeadEncryptXChaCha20Poly1305(key, nonce, pt, aad);
      expect(hex(sealed), c.name).toBe(c.ciphertext_with_tag_hex);
      expect(hex(aeadDecryptXChaCha20Poly1305(key, nonce, sealed, aad)), c.name).toBe(c.plaintext_hex);
    }
  });

  it("sealLocalV2: one nonce draw, the self AAD, the listed ciphertext", () => {
    const v = file.seal_local_v2;
    const rng = scriptedRandomness(providerName);
    const aad = buildSelfSealAadV2(v.device_id);
    expect(hex(aad)).toBe(v.aad_cbor_hex);
    rng.load(v.draws);
    const key32 = unhex(v.key_hex);
    const sealed = sealLocalV2({ key32, aad, plaintext: unhex(v.plaintext_hex) });
    expect(rng.remaining()).toBe(0);
    expect(sealed.nonce_b64).toBe(v.header.nonce); // the vector's self header names it `nonce`
    expect(sealed.ciphertext_b64).toBe(hexToB64(v.ciphertext_with_tag_hex));
    expect(hex(openLocalV2({ key32, aad, ...sealed }))).toBe(v.plaintext_hex);
    expect(v.header).toEqual({ v: 2, kind: "self", nonce: sealed.nonce_b64 });
  });
});

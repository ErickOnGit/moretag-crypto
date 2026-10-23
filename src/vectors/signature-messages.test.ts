/**
 * The two signing messages' golden bytes:
 * - vectors/spk-sig-msg-v1.json, the library's original file (the app's and the
 *   server's golden-vector tests rely on its bytes), unchanged;
 * - vectors/spk-sig-msg-v1-independent.json, the independent generator's;
 * - vectors/opk-batch-sig-msg-v1.json, the one-time prekey batch.
 * Each is checked against the library and against the independent generator's own
 * CBOR encoder, taken from its source without importing the library into it.
 */
import { it, expect } from "vitest";
import * as nodeCrypto from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { hex, loadVector, unhex } from "./support.js";
import { buildOpkBatchSigMessage, buildSpkSigMessage } from "../crypto/x3dh.js";
import { ed25519Sign, ed25519Verify } from "../crypto/ed25519.js";
import { X3DHPrekeyManagerV2 } from "../x3dh/prekey-manager.js";
import { bytesToBase64 } from "../encoding/base64.js";

const GENERATOR = readFileSync(join(process.cwd(), "scripts", "gen-vectors-v2.mjs"), "utf-8");

/**
 * The generator's `cbor` function and the three helpers it uses, cut from its
 * source by name and evaluated alone (nothing else of the script runs).
 */
function generatorCbor(): (value: unknown) => Buffer {
  const cut = (start: string, end: string) => {
    const from = GENERATOR.indexOf(start);
    const to = GENERATOR.indexOf(end, from);
    if (from < 0 || to < 0) throw new Error(`generator source: ${start} not found`);
    return GENERATOR.slice(from, to);
  };
  const helpers = [
    cut("const utf8 = ", "\n"),
    cut("const cat = ", "\n"),
    cut("function fail(message) {", "\n}\n") + "\n}\n",
    cut("function cborHead(major, value) {", "// RFC 8949 Appendix A"),
  ].join("\n");
  return new Function("Buffer", `${helpers}\nreturn cbor;`)(Buffer) as (value: unknown) => Buffer;
}

it("the generator imports only node:crypto, node:fs and node:path", () => {
  const specifiers = [...GENERATOR.matchAll(/^\s*import\s[^'"]*['"]([^'"]+)['"]/gm)].map((m) => m[1]);
  expect(specifiers.sort()).toEqual(["node:crypto", "node:fs", "node:path"]);
  expect(GENERATOR).not.toMatch(/\brequire\s*\(/);
  expect(GENERATOR).not.toMatch(/\bimport\s*\(/);
});

it("the library's original spk-sig-msg-v1.json is unchanged and reproduced", () => {
  const v = loadVector("spk-sig-msg-v1.json");
  const msg = buildSpkSigMessage({
    recipient_device_id: v.recipient_device_id,
    ik_pub32: unhex(v.ik_pub_hex),
    spk_pub32: unhex(v.spk_pub_hex),
    spk_id: v.spk_id,
  });
  expect(bytesToBase64(msg)).toBe(v.message_b64);
  // The independent generator's own CBOR encoder gives the same bytes for the same inputs.
  const cbor = generatorCbor();
  expect(
    bytesToBase64(cbor(["moretag/x3dh/spk/v1", v.recipient_device_id, Buffer.from(v.ik_pub_hex, "hex"), Buffer.from(v.spk_pub_hex, "hex"), v.spk_id]))
  ).toBe(v.message_b64);
});

it("the independent spk-sig-msg-v1-independent.json: message and signature", () => {
  const v = loadVector("spk-sig-msg-v1-independent.json");
  const msg = buildSpkSigMessage({
    recipient_device_id: v.device_id,
    ik_pub32: unhex(v.ik_public_hex),
    spk_pub32: unhex(v.spk_public_hex),
    spk_id: v.spk_id,
  });
  expect(hex(msg)).toBe(v.message_cbor_hex);
  expect(hex(ed25519Sign(unhex(v.ik_sig_seed_hex), msg))).toBe(v.signature_hex);
  expect(ed25519Verify(unhex(v.ik_sig_public_hex), msg, unhex(v.signature_hex))).toBe(true);
});

it("opk-batch-sig-msg-v1.json: library, generator CBOR and node:crypto agree", () => {
  const v = loadVector("opk-batch-sig-msg-v1.json");
  const prekeys = v.prekeys.map((p: any) => ({ opk_id: p.opk_id, pub32: unhex(p.pub_hex) }));
  const msg = buildOpkBatchSigMessage({ device_id: v.device_id, prekeys });
  expect(hex(msg)).toBe(v.message_cbor_hex);

  const cbor = generatorCbor();
  const independent = cbor([v.domain, v.device_id, v.prekeys.map((p: any) => [p.opk_id, Buffer.from(p.pub_hex, "hex")])]);
  expect(independent.toString("hex")).toBe(v.message_cbor_hex);

  expect(hex(ed25519Sign(unhex(v.ik_sig_seed_hex), msg))).toBe(v.signature_hex);
  const key = nodeCrypto.createPrivateKey({
    key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.from(v.ik_sig_seed_hex, "hex")]),
    format: "der",
    type: "pkcs8",
  });
  expect(nodeCrypto.sign(null, Buffer.from(msg), key).toString("hex")).toBe(v.signature_hex);

  // The prekey manager, holding those keys, signs the same batch to the same bytes.
  const b64 = (h: string) => bytesToBase64(unhex(h));
  const bob = X3DHPrekeyManagerV2.fromState({
    v: 2,
    recipient_device_id: v.device_id,
    ik_x25519_priv_b64: bytesToBase64(new Uint8Array(32).fill(7)),
    ik_x25519_pub_b64: bytesToBase64(new Uint8Array(32).fill(8)),
    ik_ed25519_priv_b64: b64(v.ik_sig_seed_hex),
    ik_ed25519_pub_b64: b64(v.ik_sig_public_hex),
    current_spk_id: null,
    spks: [],
    opks: v.prekeys.map((p: any) => ({
      opk_id: p.opk_id,
      priv32_b64: bytesToBase64(new Uint8Array(32).fill(9)),
      pub32_b64: b64(p.pub_hex),
      created_at_ms: 0,
    })),
    next_opk_id: 2 ** 31,
  });
  const signed = bob.signOneTimePrekeyBatch(v.prekeys.map((p: any) => p.opk_id));
  expect(signed.batch_sig_b64).toBe(b64(v.signature_hex));
  expect(signed.prekeys).toEqual(v.prekeys.map((p: any) => ({ opk_id: p.opk_id, pub_b64: b64(p.pub_hex) })));
});

/**
 * The two signing messages' golden bytes:
 * - vectors/spk-sig-msg-v1.json, the library's v1 golden file, unchanged;
 * - vectors/spk-sig-msg-v1-independent.json, the independent generator's;
 * - vectors/opk-batch-sig-msg-v1.json, the one-time prekey batch, written by the
 *   library and checked here against the generator's CBOR encoder and node:crypto;
 * - the vectors the app and the server pin in their own tests, which are not any of
 *   these files: the signed-prekey vector (device 5a0b6f2e-…, from the app's
 *   signedPrekeyCborVector.test.ts and the server's _shared/spkSigMessage.test.ts)
 *   and the server's batch vector (_shared/opkBatchSigMessage.test.ts). Their
 *   values are copied here, never imported, so the library proves the bytes those
 *   tests depend on; a change on either side must change both copies.
 */
import { it, expect } from "vitest";
import * as nodeCrypto from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { hex, loadVector, unhex } from "./support.js";
import { buildOpkBatchSigMessage, buildSpkSigMessage } from "../crypto/x3dh.js";
import { ed25519Sign, ed25519Verify } from "../crypto/ed25519.js";
import { x25519PublicFromPrivate } from "../crypto/x25519.js";
import { getPrimitives } from "../crypto/primitives.js";

const ed25519GetPublicKey = (seed32: Uint8Array) => getPrimitives().ed25519GetPublicKey(seed32);
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

/**
 * Every module a source loads statically: `import … from`, `export … from` and a
 * bare `import '…'`. Dynamic loading (`import(`, `require(`) is refused separately.
 */
function moduleSpecifiers(source: string): string[] {
  const fromClauses = [...source.matchAll(/\b(?:import|export)\b[^'"`;]*?\bfrom\s*(['"])([^'"]+)\1/g)].map((m) => m[2]!);
  const bare = [...source.matchAll(/\bimport\s*(['"])([^'"]+)\1/g)].map((m) => m[2]!);
  return [...new Set([...fromClauses, ...bare])].sort();
}

it("the import guard sees every static form", () => {
  const sample = [
    "import crypto from 'node:crypto';",
    'import { a,\n  b } from "node:fs";',
    "import * as p from 'node:path';",
    "export { x } from '../dist/index.js';",
    'export * from "../src/index.ts";',
    "import './side-effect.js';",
  ].join("\n");
  expect(moduleSpecifiers(sample)).toEqual(
    ["../dist/index.js", "../src/index.ts", "./side-effect.js", "node:crypto", "node:fs", "node:path"].sort()
  );
});

it("the generator imports only node:crypto, node:fs and node:path", () => {
  expect(moduleSpecifiers(GENERATOR)).toEqual(["node:crypto", "node:fs", "node:path"]);
  expect(GENERATOR).not.toMatch(/\brequire\s*\(/);
  expect(GENERATOR).not.toMatch(/\bimport\s*\(/);
});

it("the app's and the server's signed-prekey vector (device 5a0b6f2e-…): message for each spk_id width, and signature", () => {
  // Copied from the server's _shared/spkSigMessage.test.ts and the app's
  // signedPrekeyCborVector.test.ts (synthetic keys: each private half is 32 consecutive bytes).
  const DEVICE_ID = "5a0b6f2e-3c41-4d8a-9e7f-1b2c3d4e5f60";
  const IK_X25519_PRIV = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
  const IK_X25519_PUB = "07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c";
  const IK_ED25519_SEED = "2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40";
  const IK_ED25519_PUB = "e7f162a10bec559afea195e4dce84b69568d5d2cb0963eb446c0685e2b17f2f0";
  const SPK_PRIV = "4142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60";
  const SPK_PUB = "64b101b1d0be5a8704bd078f9895001fc03e8e9f9522f188dd128d9846d48466";
  const MESSAGE_BEFORE_SPK_ID_HEX =
    "85" + // array(5)
    "73" + // text(19)
    "6d6f72657461672f783364682f73706b2f7631" + // "moretag/x3dh/spk/v1"
    "7824" + // text(36)
    "35613062366632652d336334312d346438612d396537662d316232633364346535663630" + // DEVICE_ID
    "5820" + // bytes(32), never tag 64
    IK_X25519_PUB +
    "5820" +
    SPK_PUB;
  const SIGNATURE_SPK_ID_1 =
    "8bc305cc5ee37628bc77211c98a1b8f1705053b54027b75b3c5ca7351d7a04aa" +
    "b1fde5ab530dc43462679147ed98ad7237517ef9680f96debf52a71ee36cce05";

  // The public halves are the private halves' keys.
  expect(hex(x25519PublicFromPrivate(unhex(IK_X25519_PRIV)))).toBe(IK_X25519_PUB);
  expect(hex(x25519PublicFromPrivate(unhex(SPK_PRIV)))).toBe(SPK_PUB);
  expect(hex(ed25519GetPublicKey(unhex(IK_ED25519_SEED)))).toBe(IK_ED25519_PUB);

  const message = (spk_id: number) =>
    buildSpkSigMessage({ recipient_device_id: DEVICE_ID, ik_pub32: unhex(IK_X25519_PUB), spk_pub32: unhex(SPK_PUB), spk_id });
  for (const [spkId, encoded] of [
    [1, "01"],
    [23, "17"],
    [24, "1818"],
    [255, "18ff"],
    [256, "190100"],
    [65535, "19ffff"],
    [65536, "1a00010000"],
  ] as const) {
    expect(hex(message(spkId)), `spk_id ${spkId}`).toBe(MESSAGE_BEFORE_SPK_ID_HEX + encoded);
  }
  expect(hex(ed25519Sign(unhex(IK_ED25519_SEED), message(1)))).toBe(SIGNATURE_SPK_ID_1);
  expect(ed25519Verify(unhex(IK_ED25519_PUB), message(1), unhex(SIGNATURE_SPK_ID_1))).toBe(true);
});

it("the server's one-time prekey batch vector (device 5a0b6f2e-…, RFC 8032 test 1's key): message and signature", () => {
  // Copied from the server's _shared/opkBatchSigMessage.test.ts; the bytes are written out field by field.
  const DEVICE_ID = "5a0b6f2e-3c41-4d8a-9e7f-1b2c3d4e5f60";
  const PREKEYS = [
    { opk_id: 1, pub32: unhex("11".repeat(32)) },
    { opk_id: 24, pub32: unhex("22".repeat(32)) },
    { opk_id: 2147483647, pub32: unhex("33".repeat(32)) },
  ];
  const MESSAGE_HEX = [
    "83", // array(3)
    "7819", // text(25)
    "6d6f72657461672f783364682f6f706b2d62617463682f7631", // "moretag/x3dh/opk-batch/v1"
    "7824", // text(36)
    "35613062366632652d336334312d346438612d396537662d316232633364346535663630", // DEVICE_ID
    "83", // array(3): the prekeys, in the order given
    "82" + "01" + "5820" + "11".repeat(32), // [1, bytes(32)], never tag 64
    "82" + "1818" + "5820" + "22".repeat(32), // [24, bytes(32)]
    "82" + "1a7fffffff" + "5820" + "33".repeat(32), // [2147483647, bytes(32)]
  ].join("");
  // RFC 8032 §7.1 test 1.
  const SECRET = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
  const PUBLIC = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
  const SIGNATURE =
    "57c5dbde99461153a10cf08a75b45dc625835aa3e8ffda769b01a314353ecef2" +
    "a37321a32e0a8e8ead8263238097e50844ee805a122e0ba4afdaf02bfe3b2407";

  const msg = buildOpkBatchSigMessage({ device_id: DEVICE_ID, prekeys: PREKEYS });
  expect(hex(msg)).toBe(MESSAGE_HEX);
  expect(hex(ed25519GetPublicKey(unhex(SECRET)))).toBe(PUBLIC);
  expect(hex(ed25519Sign(unhex(SECRET), msg))).toBe(SIGNATURE);
  expect(ed25519Verify(unhex(PUBLIC), msg, unhex(SIGNATURE))).toBe(true);
  // The independent generator's CBOR encoder agrees.
  const cbor = generatorCbor();
  expect(
    cbor(["moretag/x3dh/opk-batch/v1", DEVICE_ID, PREKEYS.map((p) => [p.opk_id, Buffer.from(p.pub32)])]).toString("hex")
  ).toBe(MESSAGE_HEX);
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

import { readFileSync } from "fs";
import { join } from "path";
import { expect, test } from "vitest";
import { encodeAADFromHeaderV1 } from "../crypto/aad.js";
import { buildSpkSigMessage } from "../crypto/x3dh.js";
import { bytesToBase64 } from "../encoding/base64.js";

function loadJson(name: string): any {
  const file = readFileSync(join(process.cwd(), "vectors", name), "utf-8");
  return JSON.parse(file);
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

test("delivery AAD vector matches encoding output", () => {
  const vector = loadJson("delivery-aad-v1.json");
  const aad = encodeAADFromHeaderV1(vector.header);
  expect(bytesToBase64(aad)).toBe(vector.aad_b64);
});

test("SPK signature message vector matches CBOR encoding", () => {
  const vector = loadJson("spk-sig-msg-v1.json");
  const msg = buildSpkSigMessage({
    recipient_device_id: vector.recipient_device_id,
    ik_pub32: hexToBytes(vector.ik_pub_hex),
    spk_pub32: hexToBytes(vector.spk_pub_hex),
    spk_id: vector.spk_id,
  });
  expect(bytesToBase64(msg)).toBe(vector.message_b64);
});

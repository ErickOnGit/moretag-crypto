import { test, expect } from "vitest";
import {
  buildSelfSealAadV2,
  openDeliveryV2,
  openLocalV2,
  sealDeliveryV2,
  sealLocalV2,
} from "./seal.js";
import { buildAssociatedDataV2 } from "./ad.js";
import { randomNonce24 } from "./aead.js";
import { randomBytes } from "@noble/ciphers/utils.js";
import { bytesToBase64 } from "../encoding/base64.js";
import type { HeaderProtoV2 } from "../wire/header.js";
import { MAX_PLAINTEXT_BYTES, MAX_CIPHERTEXT_BYTES } from "./limits.js";
import { DecryptFailedError, InvalidDeviceIdError, InvalidWireError } from "../errors.js";
import { ALICE_DEVICE, BOB_DEVICE, CAROL_DEVICE, utf8 } from "../test-fixtures.js";

function ad(devB = BOB_DEVICE): Uint8Array {
  return buildAssociatedDataV2({
    initiator_ik_pub32: randomBytes(32),
    responder_ik_pub32: randomBytes(32),
    initiator_ik_sig_pub32: randomBytes(32),
    responder_ik_sig_pub32: randomBytes(32),
    initiator_device_id: ALICE_DEVICE,
    responder_device_id: devB,
  });
}

function header(over: Partial<HeaderProtoV2> = {}): HeaderProtoV2 {
  return {
    v: 2,
    alg: "xchacha20poly1305",
    nonce_b64: bytesToBase64(randomNonce24()),
    sender_device_id: ALICE_DEVICE,
    recipient_device_id: BOB_DEVICE,
    dr: { dh_pub_b64: bytesToBase64(randomBytes(32)), pn: 0, n: 1 },
    ...over,
  };
}

test("delivery roundtrip returns original plaintext", () => {
  const key32 = randomBytes(32);
  const AD = ad();
  const h = header();
  const plaintext = utf8("Secret message");
  const { ciphertext_b64 } = sealDeliveryV2({ key32, ad: AD, header: h, plaintext });
  expect(openDeliveryV2({ key32, ad: AD, header: h, ciphertext_b64 })).toEqual(plaintext);
});

test("tampered ciphertext, header, AD or key fail authentication", () => {
  const key32 = randomBytes(32);
  const AD = ad();
  const h = header();
  const { ciphertext_b64 } = sealDeliveryV2({ key32, ad: AD, header: h, plaintext: utf8("x") });
  const ct = Buffer.from(ciphertext_b64, "base64");
  ct[0]! ^= 1;
  const cases = [
    { key32, ad: AD, header: h, ciphertext_b64: ct.toString("base64") },
    { key32, ad: AD, header: { ...h, dr: { ...h.dr, n: 2 } }, ciphertext_b64 },
    { key32, ad: AD, header: { ...h, grp: { gid: CAROL_DEVICE, epoch: 1 } }, ciphertext_b64 },
    { key32, ad: ad(), header: h, ciphertext_b64 },
    { key32: randomBytes(32), ad: AD, header: h, ciphertext_b64 },
  ];
  for (const c of cases) expect(() => openDeliveryV2(c)).toThrow(DecryptFailedError);
});

test("a malformed header is refused with its code before the AEAD", () => {
  const key32 = randomBytes(32);
  const AD = ad();
  const bad: Array<[HeaderProtoV2, string]> = [
    [header({ nonce_b64: bytesToBase64(randomBytes(23)) }), "invalid_header"],
    [header({ nonce_b64: "not base64!" }), "invalid_header"],
    [header({ dr: { dh_pub_b64: bytesToBase64(randomBytes(31)), pn: 0, n: 1 } }), "invalid_header"],
    [header({ sender_device_id: "sender-uuid" }), "invalid_device_id"],
    [{ ...header(), grp: { gid: "g", epoch: 1 } }, "invalid_grp"],
  ];
  for (const [h, code] of bad) {
    let err: unknown;
    try {
      sealDeliveryV2({ key32, ad: AD, header: h, plaintext: utf8("x") });
    } catch (e) {
      err = e;
    }
    expect(err instanceof InvalidWireError || err instanceof InvalidDeviceIdError).toBe(true);
    expect((err as InvalidWireError).code).toBe(code);
  }
});

test("a malformed AD is refused", () => {
  expect(() =>
    sealDeliveryV2({ key32: randomBytes(32), ad: new Uint8Array(164), header: header(), plaintext: utf8("x") })
  ).toThrow(TypeError);
});

test("invalid base64 for ciphertext_b64 throws TypeError", () => {
  expect(() =>
    openDeliveryV2({ key32: randomBytes(32), ad: ad(), header: header(), ciphertext_b64: "!!!" })
  ).toThrow(TypeError);
});

test("plaintext and ciphertext limits are enforced", () => {
  expect(() =>
    sealDeliveryV2({ key32: randomBytes(32), ad: ad(), header: header(), plaintext: new Uint8Array(MAX_PLAINTEXT_BYTES + 1) })
  ).toThrow(/Plaintext too large/);
  const huge = bytesToBase64(new Uint8Array(MAX_CIPHERTEXT_BYTES + 3));
  expect(() =>
    openDeliveryV2({ key32: randomBytes(32), ad: ad(), header: header(), ciphertext_b64: huge })
  ).toThrow(/Ciphertext too large/);
});

test("local seal: a fresh nonce per seal, round trip under the self AAD, and the AAD binds the device", () => {
  const key32 = randomBytes(32);
  const aad = buildSelfSealAadV2(ALICE_DEVICE);
  const a = sealLocalV2({ key32, aad, plaintext: utf8("note") });
  const b = sealLocalV2({ key32, aad, plaintext: utf8("note") });
  expect(a.nonce_b64).not.toBe(b.nonce_b64);
  expect(openLocalV2({ key32, aad, ...a })).toEqual(utf8("note"));
  expect(() => openLocalV2({ key32, aad: buildSelfSealAadV2(BOB_DEVICE), ...a })).toThrow(DecryptFailedError);
  expect(() => openLocalV2({ key32: randomBytes(32), aad, ...a })).toThrow(DecryptFailedError);
});

test("the self AAD is CBOR [\"moretag/self/v1\", device_id] and needs a canonical id", () => {
  const aad = buildSelfSealAadV2(ALICE_DEVICE);
  const expected = Buffer.concat([
    Buffer.from([0x82, 0x6f]),
    Buffer.from("moretag/self/v1"),
    Buffer.from([0x78, 0x24]),
    Buffer.from(ALICE_DEVICE),
  ]);
  expect(Buffer.from(aad).toString("hex")).toBe(expected.toString("hex"));
  expect(() => buildSelfSealAadV2("alice-device")).toThrow(InvalidDeviceIdError);
});

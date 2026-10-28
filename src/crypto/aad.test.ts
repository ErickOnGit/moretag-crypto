import { test, expect } from "vitest";
import { buildDeliveryAadV2, encodeHeaderV2 } from "./aad.js";
import { buildAssociatedDataV2 } from "./ad.js";
import type { HeaderProtoV2 } from "../wire/header.js";
import { InvalidDeviceIdError, InvalidWireError } from "../errors.js";
import { bytesToBase64 } from "../encoding/base64.js";
import { ALICE_DEVICE, BOB_DEVICE, CAROL_DEVICE } from "../test-fixtures.js";

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const raw = (id: string) => id.replace(/-/g, "");
const nonce = new Uint8Array(24).fill(0xaa);
const dh = new Uint8Array(32).fill(0xbb);

function header(over: Partial<HeaderProtoV2> = {}): HeaderProtoV2 {
  return {
    v: 2,
    alg: "xchacha20poly1305",
    nonce_b64: bytesToBase64(nonce),
    sender_device_id: ALICE_DEVICE,
    recipient_device_id: BOB_DEVICE,
    dr: { dh_pub_b64: bytesToBase64(dh), pn: 3, n: 300 },
    ...over,
  };
}

const AD = buildAssociatedDataV2({
  initiator_ik_pub32: new Uint8Array(32).fill(1),
  responder_ik_pub32: new Uint8Array(32).fill(2),
  initiator_ik_sig_pub32: new Uint8Array(32).fill(3),
  responder_ik_sig_pub32: new Uint8Array(32).fill(4),
  initiator_device_id: ALICE_DEVICE,
  responder_device_id: BOB_DEVICE,
});

test("H is the 9-element CBOR array with null for a pairwise message", () => {
  expect(hex(encodeHeaderV2(header()))).toBe(
    "89" + // array(9)
      "02" +
      "71" + hex(new TextEncoder().encode("xchacha20poly1305")) +
      "5818" + "aa".repeat(24) +
      "50" + raw(ALICE_DEVICE) +
      "50" + raw(BOB_DEVICE) +
      "5820" + "bb".repeat(32) +
      "03" +
      "19012c" +
      "f6"
  );
});

test("a group slot is [gid (bstr 16), epoch], shortest form", () => {
  const h = encodeHeaderV2(header({ grp: { gid: CAROL_DEVICE, epoch: 2 ** 32 } }));
  expect(hex(h).endsWith("82" + "50" + raw(CAROL_DEVICE) + "1b0000000100000000")).toBe(true);
});

test("the AAD is AD || H, and extra header keys never enter it", () => {
  const aad = buildDeliveryAadV2(AD, header());
  expect(hex(aad)).toBe(hex(AD) + hex(encodeHeaderV2(header())));
  const withSidecar = { ...header(), session_init: { anything: true } } as HeaderProtoV2;
  expect(hex(buildDeliveryAadV2(AD, withSidecar))).toBe(hex(aad));
});

test("every header field changes H", () => {
  const base = hex(encodeHeaderV2(header()));
  const variants: HeaderProtoV2[] = [
    header({ nonce_b64: bytesToBase64(new Uint8Array(24).fill(0xab)) }),
    header({ sender_device_id: CAROL_DEVICE }),
    header({ recipient_device_id: CAROL_DEVICE }),
    header({ dr: { dh_pub_b64: bytesToBase64(new Uint8Array(32).fill(0xbc)), pn: 3, n: 300 } }),
    header({ dr: { dh_pub_b64: bytesToBase64(dh), pn: 4, n: 300 } }),
    header({ dr: { dh_pub_b64: bytesToBase64(dh), pn: 3, n: 301 } }),
    header({ grp: { gid: CAROL_DEVICE, epoch: 0 } }),
  ];
  for (const v of variants) expect(hex(encodeHeaderV2(v))).not.toBe(base);
});

test("a malformed header or AD is refused before any bytes are built", () => {
  expect(() => encodeHeaderV2(header({ sender_device_id: "alice-device" }))).toThrow(InvalidDeviceIdError);
  expect(() => encodeHeaderV2(header({ nonce_b64: bytesToBase64(new Uint8Array(12)) }))).toThrow(InvalidWireError);
  expect(() => buildDeliveryAadV2(new Uint8Array(164), header())).toThrow(TypeError);
});

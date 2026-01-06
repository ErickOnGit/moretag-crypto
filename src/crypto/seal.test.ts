import { test, expect } from "vitest";
import {
  sealDeliveryV1,
  openDeliveryV1,
  sealArchiveV1,
  openArchiveV1,
} from "./seal.js";
import { randomNonce24 } from "./aead.js";
import { randomBytes } from "@noble/ciphers/utils.js";
import { bytesToBase64 } from "../encoding/base64.js";
import type { HeaderProtoV1, ArchiveHeaderV1 } from "../wire/header.js";

test("delivery roundtrip returns original plaintext", () => {
  const key = randomBytes(32);
  const nonce = randomNonce24();
  const dhPub = randomBytes(32);
  const plaintext = new TextEncoder().encode("Secret message");

  const header: HeaderProtoV1 = {
    v: 1,
    alg: "xchacha20poly1305",
    nonce_b64: bytesToBase64(nonce),
    sender_device_id: "sender-uuid",
    recipient_device_id: "recipient-uuid",
    dr: {
      dh_pub_b64: bytesToBase64(dhPub),
      pn: 0,
      n: 1,
    },
  };

  const { ciphertext_b64 } = sealDeliveryV1({ key32: key, header, plaintext });
  const decrypted = openDeliveryV1({ key32: key, header, ciphertext_b64 });

  expect(decrypted).toEqual(plaintext);
});

test("archive roundtrip returns original plaintext", () => {
  const key = randomBytes(32);
  const nonce = randomNonce24();
  const dhPub = randomBytes(32);
  const plaintext = new TextEncoder().encode("Archive data");

  const header: ArchiveHeaderV1 = {
    v: 1,
    alg: "xchacha20poly1305",
    nonce_b64: bytesToBase64(nonce),
    sender_device_id: "sender-uuid",
    dr: {
      dh_pub_b64: bytesToBase64(dhPub),
      pn: 0,
      n: 1,
    },
  };

  const { ciphertext_b64 } = sealArchiveV1({ key32: key, header, plaintext });
  const decrypted = openArchiveV1({ key32: key, header, ciphertext_b64 });

  expect(decrypted).toEqual(plaintext);
});

test("tampered ciphertext causes decrypt to throw", () => {
  const key = randomBytes(32);
  const nonce = randomNonce24();
  const dhPub = randomBytes(32);
  const plaintext = new TextEncoder().encode("Message");

  const header: HeaderProtoV1 = {
    v: 1,
    alg: "xchacha20poly1305",
    nonce_b64: bytesToBase64(nonce),
    sender_device_id: "sender-uuid",
    recipient_device_id: "recipient-uuid",
    dr: {
      dh_pub_b64: bytesToBase64(dhPub),
      pn: 0,
      n: 1,
    },
  };

  const { ciphertext_b64 } = sealDeliveryV1({ key32: key, header, plaintext });

  // Tamper with the base64 ciphertext by replacing a character
  const tampered = ciphertext_b64.slice(0, -1) + "X";

  expect(() =>
    openDeliveryV1({ key32: key, header, ciphertext_b64: tampered })
  ).toThrow();
});

test("tampered AAD (header field) causes decrypt to throw", () => {
  const key = randomBytes(32);
  const nonce = randomNonce24();
  const dhPub = randomBytes(32);
  const plaintext = new TextEncoder().encode("Message");

  const header: HeaderProtoV1 = {
    v: 1,
    alg: "xchacha20poly1305",
    nonce_b64: bytesToBase64(nonce),
    sender_device_id: "sender-uuid",
    recipient_device_id: "recipient-uuid",
    dr: {
      dh_pub_b64: bytesToBase64(dhPub),
      pn: 0,
      n: 1,
    },
  };

  const { ciphertext_b64 } = sealDeliveryV1({ key32: key, header, plaintext });

  // Change header field (tampers AAD)
  const tamperedHeader = { ...header, sender_device_id: "attacker-uuid" };

  expect(() =>
    openDeliveryV1({ key32: key, header: tamperedHeader, ciphertext_b64 })
  ).toThrow();
});

test("wrong key causes decrypt to throw", () => {
  const key = randomBytes(32);
  const wrongKey = randomBytes(32);
  const nonce = randomNonce24();
  const dhPub = randomBytes(32);
  const plaintext = new TextEncoder().encode("Message");

  const header: HeaderProtoV1 = {
    v: 1,
    alg: "xchacha20poly1305",
    nonce_b64: bytesToBase64(nonce),
    sender_device_id: "sender-uuid",
    recipient_device_id: "recipient-uuid",
    dr: {
      dh_pub_b64: bytesToBase64(dhPub),
      pn: 0,
      n: 1,
    },
  };

  const { ciphertext_b64 } = sealDeliveryV1({ key32: key, header, plaintext });

  expect(() =>
    openDeliveryV1({ key32: wrongKey, header, ciphertext_b64 })
  ).toThrow();
});

test("nonce length enforcement: wrong length throws TypeError", () => {
  const key = randomBytes(32);
  const badNonce = randomBytes(23); // Wrong length: 23 instead of 24
  const dhPub = randomBytes(32);
  const plaintext = new TextEncoder().encode("Message");

  const header: HeaderProtoV1 = {
    v: 1,
    alg: "xchacha20poly1305",
    nonce_b64: bytesToBase64(badNonce),
    sender_device_id: "sender-uuid",
    recipient_device_id: "recipient-uuid",
    dr: {
      dh_pub_b64: bytesToBase64(dhPub),
      pn: 0,
      n: 1,
    },
  };

  expect(() => sealDeliveryV1({ key32: key, header, plaintext })).toThrowError(
    /Invalid nonce length.*expected 24 bytes, got 23/
  );
});

test("dh_pub length enforcement: wrong length throws TypeError", () => {
  const key = randomBytes(32);
  const nonce = randomNonce24();
  const badDhPub = randomBytes(31); // Wrong length: 31 instead of 32
  const plaintext = new TextEncoder().encode("Message");

  const header: HeaderProtoV1 = {
    v: 1,
    alg: "xchacha20poly1305",
    nonce_b64: bytesToBase64(nonce),
    sender_device_id: "sender-uuid",
    recipient_device_id: "recipient-uuid",
    dr: {
      dh_pub_b64: bytesToBase64(badDhPub),
      pn: 0,
      n: 1,
    },
  };

  expect(() => sealDeliveryV1({ key32: key, header, plaintext })).toThrowError(
    /Invalid dr\.dh_pub_b64 length.*expected 32 bytes, got 31/
  );
});

test("invalid base64 for nonce_b64 throws TypeError (length check catches it)", () => {
  const key = randomBytes(32);
  const dhPub = randomBytes(32);
  const plaintext = new TextEncoder().encode("Message");

  const header: HeaderProtoV1 = {
    v: 1,
    alg: "xchacha20poly1305",
    // Base64 that decodes but has wrong length
    nonce_b64: "short",
    sender_device_id: "sender-uuid",
    recipient_device_id: "recipient-uuid",
    dr: {
      dh_pub_b64: bytesToBase64(dhPub),
      pn: 0,
      n: 1,
    },
  };

  expect(() => sealDeliveryV1({ key32: key, header, plaintext })).toThrowError(
    TypeError
  );
});

test("invalid base64 for dh_pub_b64 throws TypeError (length check catches it)", () => {
  const key = randomBytes(32);
  const nonce = randomNonce24();
  const plaintext = new TextEncoder().encode("Message");

  const header: HeaderProtoV1 = {
    v: 1,
    alg: "xchacha20poly1305",
    nonce_b64: bytesToBase64(nonce),
    sender_device_id: "sender-uuid",
    recipient_device_id: "recipient-uuid",
    dr: {
      // Base64 that decodes but has wrong length
      dh_pub_b64: "short",
      pn: 0,
      n: 1,
    },
  };

  expect(() => sealDeliveryV1({ key32: key, header, plaintext })).toThrowError(
    TypeError
  );
});

test("invalid base64 for ciphertext_b64 throws TypeError", () => {
  const key = randomBytes(32);
  const nonce = randomNonce24();
  const dhPub = randomBytes(32);

  const header: HeaderProtoV1 = {
    v: 1,
    alg: "xchacha20poly1305",
    nonce_b64: bytesToBase64(nonce),
    sender_device_id: "sender-uuid",
    recipient_device_id: "recipient-uuid",
    dr: {
      dh_pub_b64: bytesToBase64(dhPub),
      pn: 0,
      n: 1,
    },
  };

  // Short/empty base64 will decode but fail length checks in AEAD
  expect(() =>
    openDeliveryV1({
      key32: key,
      header,
      ciphertext_b64: "short",
    })
  ).toThrow();
});

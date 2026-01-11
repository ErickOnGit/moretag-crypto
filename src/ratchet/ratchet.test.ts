import { describe, it, expect } from "vitest";
import { ratchetInit, ratchetEncrypt, ratchetDecrypt } from "./ratchet.js";
import { generateX25519Keypair } from "../crypto/x25519.js";
import { randomBytes } from "@noble/ciphers/utils.js";
import { MAX_PLAINTEXT_BYTES, MAX_SKIP_DERIVE } from "../crypto/limits.js";
import { bytesToBase64 } from "../encoding/base64.js";

function encode(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

describe("Double Ratchet MVP", () => {
  it("performs basic send/receive roundtrip", () => {
    const root = randomBytes(32);
    const aliceDh = generateX25519Keypair();
    const bobDh = generateX25519Keypair();

    const aliceState = ratchetInit({
      rk32: root,
      selfDh: aliceDh,
      remoteDhPub32: bobDh.pub32,
      sendingFirst: true,
    });
    const bobState = ratchetInit({
      rk32: root,
      selfDh: bobDh,
      remoteDhPub32: aliceDh.pub32,
      sendingFirst: false,
    });

    const plaintext = encode("hello bob");

    const { header, ciphertext_b64 } = ratchetEncrypt({
      state: aliceState,
      plaintext,
      sender_device_id: "alice-device",
      recipient_device_id: "bob-device",
    });

    const { plaintext: decrypted } = ratchetDecrypt({
      state: bobState,
      header,
      ciphertext_b64,
    });

    expect(decrypted).toEqual(plaintext);
  });

  it("handles out-of-order receive using skipped message keys", () => {
    const root = randomBytes(32);
    const aliceDh = generateX25519Keypair();
    const bobDh = generateX25519Keypair();

    const aliceState = ratchetInit({
      rk32: root,
      selfDh: aliceDh,
      remoteDhPub32: bobDh.pub32,
      sendingFirst: true,
    });
    const bobState = ratchetInit({
      rk32: root,
      selfDh: bobDh,
      remoteDhPub32: aliceDh.pub32,
      sendingFirst: false,
    });

    const msg1 = encode("m1");
    const msg2 = encode("m2");

    const enc1 = ratchetEncrypt({
      state: aliceState,
      plaintext: msg1,
      sender_device_id: "alice-device",
      recipient_device_id: "bob-device",
    });
    const enc2 = ratchetEncrypt({
      state: aliceState,
      plaintext: msg2,
      sender_device_id: "alice-device",
      recipient_device_id: "bob-device",
    });

    // Bob receives second message first
    const dec2 = ratchetDecrypt({
      state: bobState,
      header: enc2.header,
      ciphertext_b64: enc2.ciphertext_b64,
    });
    expect(dec2.plaintext).toEqual(msg2);

    // Then first message from skipped cache
    const dec1 = ratchetDecrypt({
      state: bobState,
      header: enc1.header,
      ciphertext_b64: enc1.ciphertext_b64,
    });
    expect(dec1.plaintext).toEqual(msg1);
  });

  it("advances DH ratchet on sender request and decrypts after receiver ratchet", () => {
    const root = randomBytes(32);
    const aliceDh = generateX25519Keypair();
    const bobDh = generateX25519Keypair();

    const aliceState = ratchetInit({
      rk32: root,
      selfDh: aliceDh,
      remoteDhPub32: bobDh.pub32,
      sendingFirst: true,
    });
    const bobState = ratchetInit({
      rk32: root,
      selfDh: bobDh,
      remoteDhPub32: aliceDh.pub32,
      sendingFirst: false,
    });

    // First message without DH advance
    const first = ratchetEncrypt({
      state: aliceState,
      plaintext: encode("first"),
      sender_device_id: "alice-device",
      recipient_device_id: "bob-device",
    });
    ratchetDecrypt({ state: bobState, header: first.header, ciphertext_b64: first.ciphertext_b64 });

    // Second message with new DH key (advanceDh=true)
    const second = ratchetEncrypt({
      state: aliceState,
      plaintext: encode("second"),
      sender_device_id: "alice-device",
      recipient_device_id: "bob-device",
      advanceDh: true,
    });

    const decSecond = ratchetDecrypt({
      state: bobState,
      header: second.header,
      ciphertext_b64: second.ciphertext_b64,
    });

    expect(decSecond.plaintext).toEqual(encode("second"));
  });

  it("rejects plaintext exceeding limit", () => {
    const root = randomBytes(32);
    const aliceDh = generateX25519Keypair();
    const bobDh = generateX25519Keypair();

    const aliceState = ratchetInit({
      rk32: root,
      selfDh: aliceDh,
      remoteDhPub32: bobDh.pub32,
      sendingFirst: true,
    });

    const oversized = new Uint8Array(MAX_PLAINTEXT_BYTES + 1);
    expect(() =>
      ratchetEncrypt({
        state: aliceState,
        plaintext: oversized,
        sender_device_id: "alice-device",
        recipient_device_id: "bob-device",
      })
    ).toThrow(/Plaintext too large/);
  });

  it("enforces receive derivation window limit", () => {
    const root = randomBytes(32);
    const aliceDh = generateX25519Keypair();
    const bobDh = generateX25519Keypair();

    const aliceState = ratchetInit({
      rk32: root,
      selfDh: aliceDh,
      remoteDhPub32: bobDh.pub32,
      sendingFirst: true,
    });
    const bobState = ratchetInit({
      rk32: root,
      selfDh: bobDh,
      remoteDhPub32: aliceDh.pub32,
      sendingFirst: false,
    });

    const header = {
      v: 1,
      alg: "xchacha20poly1305",
      nonce_b64: bytesToBase64(randomBytes(24)),
      sender_device_id: "alice-device",
      recipient_device_id: "bob-device",
      dr: {
        dh_pub_b64: bytesToBase64(aliceDh.pub32),
        pn: 0,
        n: MAX_SKIP_DERIVE + 5,
      },
    } as const;

    const ciphertext_b64 = bytesToBase64(new Uint8Array(32)); // dummy

    expect(() =>
      ratchetDecrypt({ state: bobState, header, ciphertext_b64 })
    ).toThrow(/Max skip derivation window exceeded/);

    // Ensure sender state unaffected for subsequent valid sends
    const enc = ratchetEncrypt({
      state: aliceState,
      plaintext: encode("ok"),
      sender_device_id: "alice-device",
      recipient_device_id: "bob-device",
    });
    const dec = ratchetDecrypt({
      state: bobState,
      header: enc.header,
      ciphertext_b64: enc.ciphertext_b64,
    });
    expect(dec.plaintext).toEqual(encode("ok"));
  });
});

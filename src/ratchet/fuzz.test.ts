import { describe, it, expect } from "vitest";
import { ratchetInit, ratchetEncrypt, ratchetDecrypt } from "./ratchet.js";
import { generateX25519Keypair } from "../crypto/x25519.js";
import { randomBytes } from "@noble/ciphers/utils.js";

function encode(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

describe("Ratchet fuzz (bounded)", () => {
  it("survives random reorder/drop/dupe batches and decrypts follow-up", () => {
    const trials = 5;

    for (let t = 0; t < trials; t++) {
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

      const count = 6 + t; // vary a bit
      const envelopes = [];
      for (let i = 0; i < count; i++) {
        envelopes.push(
          ratchetEncrypt({
            state: aliceState,
            plaintext: encode(`t${t}-m${i}`),
            sender_device_id: "alice",
            recipient_device_id: "bob",
            advanceDh: i === 3, // periodic DH advance
          })
        );
      }

      // Randomly drop some, duplicate some, and reorder
      const shuffled = envelopes
        .filter(() => Math.random() > 0.2) // drop ~20%
        .concat(envelopes.filter(() => Math.random() > 0.7)) // duplicate ~30%
        .sort(() => Math.random() - 0.5);

      for (const env of shuffled) {
        try {
          ratchetDecrypt({
            state: bobState,
            header: env.header,
            ciphertext_b64: env.ciphertext_b64,
          });
        } catch {
          // allowed to fail for tampered/duplicate
        }
      }

      // Follow-up must decrypt to ensure state not corrupted
      const follow = ratchetEncrypt({
        state: aliceState,
        plaintext: encode(`t${t}-follow`),
        sender_device_id: "alice",
        recipient_device_id: "bob",
      });
      const followDec = ratchetDecrypt({
        state: bobState,
        header: follow.header,
        ciphertext_b64: follow.ciphertext_b64,
      });
      expect(new TextDecoder().decode(followDec.plaintext)).toBe(`t${t}-follow`);
    }
  });
});

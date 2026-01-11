import { describe, it, expect } from "vitest";
import { ratchetInit, ratchetEncrypt, ratchetDecrypt } from "./ratchet.js";
import { generateX25519Keypair } from "../crypto/x25519.js";
import { randomBytes } from "@noble/ciphers/utils.js";

function encode(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

function shuffle<T>(arr: T[]): T[] {
  const out = [...arr];
  for (let i = out.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [out[i], out[j]] = [out[j]!, out[i]!];
  }
  return out;
}

describe("Ratchet stress (small reordering/loss/duplication)", () => {
  it("handles small reordering and duplicates within limits", () => {
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

    const messages = Array.from({ length: 10 }, (_, i) => `msg-${i}`);
    const encrypted = messages.map((m, idx) =>
      ratchetEncrypt({
        state: aliceState,
        plaintext: encode(m),
        sender_device_id: "alice",
        recipient_device_id: "bob",
        advanceDh: idx === 5, // force a DH ratchet mid-stream
      })
    );

    // Duplicate a couple of messages and drop one
    const delivery = shuffle([
      ...encrypted,
      encrypted[2]!,
      encrypted[7]!,
    ]).filter((_, idx) => idx !== 4); // drop one

    const received: string[] = [];
    for (const env of delivery) {
      try {
        const { plaintext } = ratchetDecrypt({
          state: bobState,
          header: env.header,
          ciphertext_b64: env.ciphertext_b64,
        });
        received.push(new TextDecoder().decode(plaintext));
      } catch {
        // duplicates or dropped gaps may throw; ensure no crash
      }
    }

    // Should decrypt at least half the batch despite drops/dupes
    expect(new Set(received).size).toBeGreaterThanOrEqual(messages.length / 2);

    // State should still decrypt fresh messages
    const followUp = ratchetEncrypt({
      state: aliceState,
      plaintext: encode("follow-up"),
      sender_device_id: "alice",
      recipient_device_id: "bob",
    });
    const followDec = ratchetDecrypt({
      state: bobState,
      header: followUp.header,
      ciphertext_b64: followUp.ciphertext_b64,
    });
    expect(new TextDecoder().decode(followDec.plaintext)).toBe("follow-up");
  });
});

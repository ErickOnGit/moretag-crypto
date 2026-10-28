import { describe, it, expect } from "vitest";
import { ratchetEncrypt, ratchetDecrypt, type RatchetState } from "./ratchet.js";
import { establishedPair } from "../test-fixtures.js";

function encode(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

/** Bob replies and Alice reads it, so Alice's next message starts a new DH chain. */
function turnAround(alice: RatchetState, bob: RatchetState): void {
  const reply = ratchetEncrypt({ state: bob, plaintext: encode("reply") });
  ratchetDecrypt({ state: alice, header: reply.header, ciphertext_b64: reply.ciphertext_b64 });
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
    const { alice: aliceState, bob: bobState } = establishedPair();

    const messages = Array.from({ length: 10 }, (_, i) => `msg-${i}`);
    const encrypted = messages.map((m, idx) => {
      if (idx === 5) turnAround(aliceState, bobState); // a DH step mid-stream
      return ratchetEncrypt({ state: aliceState, plaintext: encode(m) });
    });

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
    });
    const followDec = ratchetDecrypt({
      state: bobState,
      header: followUp.header,
      ciphertext_b64: followUp.ciphertext_b64,
    });
    expect(new TextDecoder().decode(followDec.plaintext)).toBe("follow-up");
  });
});

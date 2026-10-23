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

describe("Ratchet fuzz (bounded)", () => {
  it("survives random reorder/drop/dupe batches and decrypts follow-up", () => {
    const trials = 5;

    for (let t = 0; t < trials; t++) {
      const { alice: aliceState, bob: bobState } = establishedPair();

      const count = 6 + t; // vary a bit
      const envelopes = [];
      for (let i = 0; i < count; i++) {
        envelopes.push(
          ratchetEncrypt({
            state: aliceState,
            plaintext: encode(`t${t}-m${i}`),
          })
        );
        if (i === 3) turnAround(aliceState, bobState); // a DH step mid-batch
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

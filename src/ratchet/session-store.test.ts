import { describe, it, expect } from "vitest";
import { ratchetInit, ratchetEncrypt } from "./ratchet.js";
import {
  InMemoryRatchetStore,
  createPersistedSession,
  ratchetEncryptWithStore,
  ratchetDecryptWithStore,
} from "./session-store.js";
import { generateX25519Keypair } from "../crypto/x25519.js";
import { randomBytes } from "@noble/ciphers/utils.js";

function encode(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

describe("Ratchet session store", () => {
  it("persists state across encrypt/decrypt and prevents replay", async () => {
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

    const store = new InMemoryRatchetStore();
    store.save("alice->bob", createPersistedSession(aliceState));
    store.save("bob->alice", createPersistedSession(bobState));

    const { header, ciphertext_b64 } = await ratchetEncryptWithStore(
      store,
      "alice->bob",
      {
        state: aliceState, // ignored by wrapper copy
        plaintext: encode("hi"),
        sender_device_id: "alice-device",
        recipient_device_id: "bob-device",
      }
    );

    const { plaintext } = await ratchetDecryptWithStore(
      store,
      "bob->alice",
      { state: bobState, header, ciphertext_b64 }
    );
    expect(plaintext).toEqual(encode("hi"));

    // Replay should fail (message key consumed and state advanced)
    await expect(
      ratchetDecryptWithStore(store, "bob->alice", {
        state: bobState,
        header,
        ciphertext_b64,
      })
    ).rejects.toThrow();
  });

  it("increments version on every save", async () => {
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

    const store = new InMemoryRatchetStore();
    store.save("alice->bob", createPersistedSession(aliceState));
    store.save("bob->alice", createPersistedSession(bobState));

    const before = store.load("alice->bob")!;
    expect(before.version).toBe(0);

    const { header, ciphertext_b64 } = await ratchetEncryptWithStore(
      store,
      "alice->bob",
      {
        state: aliceState,
        plaintext: encode("hello"),
        sender_device_id: "alice-device",
        recipient_device_id: "bob-device",
      }
    );

    const afterEncrypt = store.load("alice->bob")!;
    expect(afterEncrypt.version).toBe(1);

    await ratchetDecryptWithStore(store, "bob->alice", {
      state: bobState,
      header,
      ciphertext_b64,
    });

    const afterDecrypt = store.load("bob->alice")!;
    expect(afterDecrypt.version).toBe(1);
  });
});

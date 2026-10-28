import { describe, it, expect, vi } from "vitest";
import { ratchetInit, type RatchetState } from "./ratchet.js";
import {
  InMemoryRatchetStore,
  createPersistedSession,
  ratchetEncryptWithStore,
  ratchetDecryptWithStore,
  type PersistedSession,
  type RatchetSessionStore,
} from "./session-store.js";
import { serializePersistedSessionV1 } from "./serialization.js";
import { DecryptFailedError, ReplayDetectedError, SessionNotFoundError } from "../errors.js";
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
        plaintext: encode("hi"),
        sender_device_id: "alice-device",
        recipient_device_id: "bob-device",
      }
    );

    const { plaintext } = await ratchetDecryptWithStore(
      store,
      "bob->alice",
      { header, ciphertext_b64 }
    );
    expect(plaintext).toEqual(encode("hi"));

    // Replay should fail (message key consumed and state advanced)
    await expect(
      ratchetDecryptWithStore(store, "bob->alice", {
        header,
        ciphertext_b64,
      })
    ).rejects.toBeInstanceOf(ReplayDetectedError);
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
        plaintext: encode("hello"),
        sender_device_id: "alice-device",
        recipient_device_id: "bob-device",
      }
    );

    const afterEncrypt = store.load("alice->bob")!;
    expect(afterEncrypt.version).toBe(1);

    await ratchetDecryptWithStore(store, "bob->alice", {
      header,
      ciphertext_b64,
    });

    const afterDecrypt = store.load("bob->alice")!;
    expect(afterDecrypt.version).toBe(1);
  });
});

function pair(): { alice: RatchetState; bob: RatchetState } {
  const root = randomBytes(32);
  const aliceDh = generateX25519Keypair();
  const bobDh = generateX25519Keypair();
  return {
    alice: ratchetInit({ rk32: root, selfDh: aliceDh, remoteDhPub32: bobDh.pub32, sendingFirst: true }),
    bob: ratchetInit({ rk32: root, selfDh: bobDh, remoteDhPub32: aliceDh.pub32, sendingFirst: false }),
  };
}

/** A store with only load and save: the helpers' non-transact path. */
class LoadSaveStore implements RatchetSessionStore {
  readonly inner = new InMemoryRatchetStore();
  load(sessionId: string): PersistedSession | undefined {
    return this.inner.load(sessionId);
  }
  save(sessionId: string, record: PersistedSession): void {
    this.inner.save(sessionId, record);
  }
}

function snapshot(store: { load(id: string): PersistedSession | undefined }, id: string): string {
  return JSON.stringify(serializePersistedSessionV1(store.load(id)!));
}

const SEND = { sender_device_id: "alice-device", recipient_device_id: "bob-device" };

describe("RatchetSessionStore.transact contract", () => {
  it("transact on a missing id throws SessionNotFoundError and never calls fn", () => {
    const fn = vi.fn((current: PersistedSession) => current);
    expect(() => new InMemoryRatchetStore().transact("missing", fn)).toThrow(SessionNotFoundError);
    expect(fn).not.toHaveBeenCalled();
  });

  it("a throwing callback persists nothing and rethrows the same error", () => {
    const store = new InMemoryRatchetStore();
    store.save("s", createPersistedSession(pair().alice));
    const before = snapshot(store, "s");
    const boom = new Error("boom");

    let caught: unknown;
    try {
      store.transact("s", (current) => {
        current.state.ns = 99;
        throw boom;
      });
    } catch (err) {
      caught = err;
    }
    expect(caught).toBe(boom);
    expect(snapshot(store, "s")).toBe(before);
  });

  it("persists and returns exactly the record fn returns", () => {
    const store = new InMemoryRatchetStore();
    store.save("s", createPersistedSession(pair().alice));
    const next = createPersistedSession(pair().bob);
    next.version = 7;

    const returned = store.transact("s", () => next);
    expect(returned).toBe(next);
    expect(snapshot(store, "s")).toBe(JSON.stringify(serializePersistedSessionV1(next)));
  });
});

describe("with-store helpers", () => {
  it("a missing id is SessionNotFoundError on the load/save path", async () => {
    const store = new LoadSaveStore();
    await expect(
      ratchetEncryptWithStore(store, "missing", { plaintext: encode("x"), ...SEND })
    ).rejects.toBeInstanceOf(SessionNotFoundError);
    const { alice } = pair();
    const sender = new InMemoryRatchetStore();
    sender.save("a", createPersistedSession(alice));
    const msg = await ratchetEncryptWithStore(sender, "a", { plaintext: encode("x"), ...SEND });
    await expect(ratchetDecryptWithStore(store, "missing", msg)).rejects.toBeInstanceOf(
      SessionNotFoundError
    );
  });

  it("a missing id is SessionNotFoundError on the transact path", async () => {
    const store = new InMemoryRatchetStore();
    await expect(
      ratchetEncryptWithStore(store, "missing", { plaintext: encode("x"), ...SEND })
    ).rejects.toBeInstanceOf(SessionNotFoundError);
  });

  it("success saves version + 1 on the load/save path", async () => {
    const { alice, bob } = pair();
    const store = new LoadSaveStore();
    store.save("a", createPersistedSession(alice));
    store.save("b", createPersistedSession(bob));

    const msg = await ratchetEncryptWithStore(store, "a", { plaintext: encode("hi"), ...SEND });
    expect(store.load("a")!.version).toBe(1);
    const { plaintext } = await ratchetDecryptWithStore(store, "b", msg);
    expect(plaintext).toEqual(encode("hi"));
    expect(store.load("b")!.version).toBe(1);
  });

  it("a failed decrypt leaves the stored record byte-identical, on both paths", async () => {
    for (const store of [new InMemoryRatchetStore(), new LoadSaveStore()]) {
      const { alice, bob } = pair();
      store.save("a", createPersistedSession(alice));
      store.save("b", createPersistedSession(bob));
      const msg = await ratchetEncryptWithStore(store, "a", { plaintext: encode("hi"), ...SEND });
      const before = snapshot(store, "b");

      const tampered = { ...msg, header: { ...msg.header, dr: { ...msg.header.dr, pn: 1 } } };
      await expect(ratchetDecryptWithStore(store, "b", tampered)).rejects.toBeInstanceOf(
        DecryptFailedError
      );
      expect(snapshot(store, "b")).toBe(before);
    }
  });

  it("take no state: the stored record is the only state (type check)", async () => {
    const { alice } = pair();
    const store = new InMemoryRatchetStore();
    store.save("a", createPersistedSession(alice));
    await ratchetEncryptWithStore(store, "a", {
      // @ts-expect-error -- passing a state to a with-store helper is a type error
      state: alice,
      plaintext: encode("x"),
      ...SEND,
    });
  });
});

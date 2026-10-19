import { describe, it, expect } from "vitest";
import { mkdtempSync, rmSync, readFileSync, writeFileSync, copyFileSync, unlinkSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { FileRatchetStore } from "./file-store.js";
import { ratchetInit, ratchetEncrypt, ratchetDecrypt } from "./ratchet.js";
import { createPersistedSession } from "./session-store.js";
import { generateX25519Keypair } from "../crypto/x25519.js";
import { randomBytes } from "@noble/ciphers/utils.js";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToBase64 } from "../encoding/base64.js";
import { MAX_SKIPPED_KEYS } from "../crypto/limits.js";

function encode(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

/** MAC exactly as FileRatchetStore writes it (envelope v2, bound to the session ID). */
function macV2(key: Uint8Array, sessionId: string, payload: unknown): string {
  const input = encode(`moretag-crypto/file-store/session/v2\0${sessionId}\0${JSON.stringify(payload)}`);
  return bytesToBase64(hmac(sha256, key, input));
}

/** 2.1.x envelope: MAC over the payload only, no `v` field. */
function legacyEnvelope(key: Uint8Array, payload: unknown): string {
  const mac_b64 = bytesToBase64(hmac(sha256, key, encode(JSON.stringify(payload))));
  return JSON.stringify({ payload, mac_b64 });
}

function newState() {
  const aliceDh = generateX25519Keypair();
  const bobDh = generateX25519Keypair();
  return ratchetInit({
    rk32: randomBytes(32),
    selfDh: aliceDh,
    remoteDhPub32: bobDh.pub32,
    sendingFirst: true,
  });
}

describe("FileRatchetStore", () => {
  it("requires a 32-byte MAC key", () => {
    const dir = mkdtempSync(join(tmpdir(), "ratchet-store-"));
    try {
      expect(() => new (FileRatchetStore as any)(dir)).toThrow(
        "macKey32 must be a 32-byte Uint8Array"
      );
      expect(() => new FileRatchetStore(dir, randomBytes(31))).toThrow(
        "macKey32 must be a 32-byte Uint8Array"
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("writes and reads session with atomic replace and prevents replay", () => {
    const dir = mkdtempSync(join(tmpdir(), "ratchet-store-"));
    try {
      const store = new FileRatchetStore(dir, randomBytes(32));

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

      store.save("alice->bob", createPersistedSession(aliceState));
      store.save("bob->alice", createPersistedSession(bobState));

      const { header, ciphertext_b64 } = ratchetEncrypt({
        state: aliceState,
        plaintext: encode("hi"),
        sender_device_id: "alice",
        recipient_device_id: "bob",
      });
      store.save("alice->bob", { version: 1, state: aliceState });

      const loadedBob = store.load("bob->alice")!;
      const decrypted = ratchetDecrypt({
        state: loadedBob.state,
        header,
        ciphertext_b64,
      });
      store.save("bob->alice", { version: loadedBob.version + 1, state: loadedBob.state });

      expect(decrypted.plaintext).toEqual(encode("hi"));

      // Replay should fail
      expect(() =>
        ratchetDecrypt({
          state: loadedBob.state,
          header,
          ciphertext_b64,
        })
      ).toThrow();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("detects simple rollback via version counter", () => {
    const dir = mkdtempSync(join(tmpdir(), "ratchet-store-"));
    try {
      const store = new FileRatchetStore(dir, randomBytes(32));
      const root = randomBytes(32);
      const aliceDh = generateX25519Keypair();
      const bobDh = generateX25519Keypair();

      const state = ratchetInit({
        rk32: root,
        selfDh: aliceDh,
        remoteDhPub32: bobDh.pub32,
        sendingFirst: true,
      });

      // Save version 2
      store.save("sess", { version: 2, state: createPersistedSession(state).state });

      // Attempt to save older version should fail
      expect(() =>
        store.save("sess", { version: 1, state: createPersistedSession(state).state })
      ).toThrow(/stale session version/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("detects tampering when MAC is enabled", () => {
    const dir = mkdtempSync(join(tmpdir(), "ratchet-store-"));
    try {
      const macKey32 = randomBytes(32);
      const store = new FileRatchetStore(dir, macKey32);

      const root = randomBytes(32);
      const aliceDh = generateX25519Keypair();
      const bobDh = generateX25519Keypair();

      const state = ratchetInit({
        rk32: root,
        selfDh: aliceDh,
        remoteDhPub32: bobDh.pub32,
        sendingFirst: true,
      });

      store.save("sess", createPersistedSession(state));

      // Tamper with the payload on disk
      const p = join(dir, "sess.json");
      const raw = readFileSync(p, "utf-8");
      const parsed = JSON.parse(raw);
      parsed.payload.version = 999;
      writeFileSync(p, JSON.stringify(parsed), "utf-8");

      expect(() => store.load("sess")).toThrow(/MAC verification failed/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("rejects unsafe session ids", () => {
    const dir = mkdtempSync(join(tmpdir(), "ratchet-store-"));
    try {
      const store = new FileRatchetStore(dir, randomBytes(32));
      const root = randomBytes(32);
      const aliceDh = generateX25519Keypair();
      const bobDh = generateX25519Keypair();

      const state = ratchetInit({
        rk32: root,
        selfDh: aliceDh,
        remoteDhPub32: bobDh.pub32,
        sendingFirst: true,
      });

      expect(() =>
        store.save("../escape", createPersistedSession(state))
      ).toThrow(/invalid path separator/);
      expect(() =>
        store.save("nested/path", createPersistedSession(state))
      ).toThrow(/invalid path separator/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("rejects corrupted persisted state shape", () => {
    const dir = mkdtempSync(join(tmpdir(), "ratchet-store-"));
    try {
      const macKey32 = randomBytes(32);
      const store = new FileRatchetStore(dir, macKey32);
      const root = randomBytes(32);
      const aliceDh = generateX25519Keypair();
      const bobDh = generateX25519Keypair();

      const state = ratchetInit({
        rk32: root,
        selfDh: aliceDh,
        remoteDhPub32: bobDh.pub32,
        sendingFirst: true,
      });

      store.save("sess", createPersistedSession(state));
      const p = join(dir, "sess.json");
      const raw = readFileSync(p, "utf-8");
      const parsed = JSON.parse(raw);
      parsed.payload.state.rk32 = parsed.payload.state.rk32.slice(0, 31);
      parsed.mac_b64 = macV2(macKey32, "sess", parsed.payload);
      writeFileSync(p, JSON.stringify(parsed), "utf-8");

      expect(() => store.load("sess")).toThrow(/Corrupt session state: state\.rk32/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("rejects a session file copied over another session's file", () => {
    const dir = mkdtempSync(join(tmpdir(), "ratchet-store-"));
    try {
      const store = new FileRatchetStore(dir, randomBytes(32));
      store.save("alice", createPersistedSession(newState()));
      store.save("bob", createPersistedSession(newState()));

      copyFileSync(join(dir, "alice.json"), join(dir, "bob.json"));

      expect(() => store.load("bob")).toThrow(/MAC verification failed/);
      expect(store.load("alice")).toBeDefined();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("rejects the 2.1.x envelope format by default", () => {
    const dir = mkdtempSync(join(tmpdir(), "ratchet-store-"));
    try {
      const macKey32 = randomBytes(32);
      const store = new FileRatchetStore(dir, macKey32);
      store.save("sess", createPersistedSession(newState()));
      const p = join(dir, "sess.json");
      const { payload } = JSON.parse(readFileSync(p, "utf-8"));
      writeFileSync(p, legacyEnvelope(macKey32, payload), "utf-8");

      expect(() => store.load("sess")).toThrow(/Legacy session file format/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("migrates the 2.1.x envelope format when allowLegacyFormat is set", () => {
    const dir = mkdtempSync(join(tmpdir(), "ratchet-store-"));
    try {
      const macKey32 = randomBytes(32);
      const state = newState();
      new FileRatchetStore(dir, macKey32).save("sess", createPersistedSession(state));
      const p = join(dir, "sess.json");
      const { payload } = JSON.parse(readFileSync(p, "utf-8"));
      writeFileSync(p, legacyEnvelope(macKey32, payload), "utf-8");

      const migrating = new FileRatchetStore(dir, macKey32, { allowLegacyFormat: true });
      const loaded = migrating.load("sess")!;
      expect(loaded.state.rk32).toEqual(state.rk32);
      migrating.save("sess", loaded);

      const rewritten = JSON.parse(readFileSync(p, "utf-8"));
      expect(rewritten.v).toBe(2);
      // After re-saving, a store without the legacy flag loads it.
      expect(new FileRatchetStore(dir, macKey32).load("sess")!.state.rk32).toEqual(state.rk32);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("still rejects a tampered 2.1.x file when allowLegacyFormat is set", () => {
    const dir = mkdtempSync(join(tmpdir(), "ratchet-store-"));
    try {
      const macKey32 = randomBytes(32);
      const store = new FileRatchetStore(dir, macKey32, { allowLegacyFormat: true });
      store.save("sess", createPersistedSession(newState()));
      const p = join(dir, "sess.json");
      const { payload } = JSON.parse(readFileSync(p, "utf-8"));
      const envelope = JSON.parse(legacyEnvelope(macKey32, payload));
      envelope.payload.state.ns = 99;
      writeFileSync(p, JSON.stringify(envelope), "utf-8");

      expect(() => store.load("sess")).toThrow(/MAC verification failed/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("rejects unknown envelope versions", () => {
    const dir = mkdtempSync(join(tmpdir(), "ratchet-store-"));
    try {
      const store = new FileRatchetStore(dir, randomBytes(32), { allowLegacyFormat: true });
      store.save("sess", createPersistedSession(newState()));
      const p = join(dir, "sess.json");
      const envelope = JSON.parse(readFileSync(p, "utf-8"));
      envelope.v = 3;
      writeFileSync(p, JSON.stringify(envelope), "utf-8");

      expect(() => store.load("sess")).toThrow(/unsupported envelope version/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  describe("rollback counter", () => {
    function setup(opts?: { allowLegacyFormat?: boolean }) {
      const dir = mkdtempSync(join(tmpdir(), "ratchet-store-"));
      const macKey32 = randomBytes(32);
      const store = new FileRatchetStore(dir, macKey32, opts);
      const state = newState();
      return { dir, macKey32, store, state };
    }

    it("is written as a signed record", () => {
      const { dir, store, state } = setup();
      try {
        store.save("sess", { version: 5, state });
        const counter = JSON.parse(readFileSync(join(dir, "sess.ver"), "utf-8"));
        expect(counter).toMatchObject({ v: 2, version: 5 });
        expect(typeof counter.mac_b64).toBe("string");
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    });

    it("rejects loading a session whose counter was deleted", () => {
      const { dir, store, state } = setup();
      try {
        store.save("sess", { version: 3, state });
        unlinkSync(join(dir, "sess.ver"));
        expect(() => store.load("sess")).toThrow(/Rollback counter missing/);
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    });

    it("detects restoring an old session file after the counter was deleted", () => {
      const { dir, store, state } = setup();
      try {
        store.save("sess", { version: 1, state });
        const oldFile = readFileSync(join(dir, "sess.json"), "utf-8");
        store.save("sess", { version: 2, state });

        writeFileSync(join(dir, "sess.json"), oldFile, "utf-8");
        expect(() => store.load("sess")).toThrow(/Rollback detected/);

        unlinkSync(join(dir, "sess.ver"));
        expect(() => store.load("sess")).toThrow(/Rollback counter missing/);
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    });

    it("rejects an edited counter", () => {
      const { dir, store, state } = setup();
      try {
        store.save("sess", { version: 4, state });
        const p = join(dir, "sess.ver");
        const counter = JSON.parse(readFileSync(p, "utf-8"));
        counter.version = 0;
        writeFileSync(p, JSON.stringify(counter), "utf-8");
        expect(() => store.load("sess")).toThrow(/rollback counter: MAC verification failed/);
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    });

    it("rejects a counter copied from another session", () => {
      const { dir, store, state } = setup();
      try {
        store.save("a", { version: 1, state });
        store.save("b", { version: 9, state });
        copyFileSync(join(dir, "a.ver"), join(dir, "b.ver"));
        expect(() => store.load("b")).toThrow(/rollback counter: MAC verification failed/);
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    });

    it("rejects garbage and the legacy plain-number format by default", () => {
      const { dir, store, state } = setup();
      try {
        store.save("sess", { version: 2, state });
        const p = join(dir, "sess.ver");

        writeFileSync(p, "not json", "utf-8");
        expect(() => store.load("sess")).toThrow(/Invalid rollback counter file/);
        expect(() => store.save("sess", { version: 3, state })).toThrow(/Invalid rollback counter file/);

        writeFileSync(p, "0", "utf-8");
        expect(() => store.load("sess")).toThrow(/Legacy rollback counter format/);
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    });

    it("migrates a legacy plain-number counter when allowLegacyFormat is set", () => {
      const { dir, macKey32, store, state } = setup({ allowLegacyFormat: true });
      try {
        store.save("sess", { version: 2, state });
        const p = join(dir, "sess.ver");

        writeFileSync(p, "3", "utf-8");
        expect(() => store.load("sess")).toThrow(/Rollback detected/); // still enforced

        writeFileSync(p, "2", "utf-8");
        const loaded = store.load("sess")!;
        store.save("sess", loaded);
        expect(JSON.parse(readFileSync(p, "utf-8")).v).toBe(2);
        expect(new FileRatchetStore(dir, macKey32).load("sess")!.version).toBe(2);
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    });

    it("recovers from a crash during a session's first save", () => {
      const { dir, store, state } = setup();
      try {
        // First save writes the counter before the session file. Simulate a crash in between.
        store.save("sess", { version: 1, state });
        unlinkSync(join(dir, "sess.json"));

        expect(store.load("sess")).toBeUndefined();
        store.save("sess", { version: 1, state }); // retry succeeds
        expect(store.load("sess")!.version).toBe(1);
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    });
  });

  describe("skipped message keys on load", () => {
    /** Rewrites the stored payload's skipped list and re-signs it, as a key holder could. */
    function storeWithSkipped(skipped: unknown) {
      const dir = mkdtempSync(join(tmpdir(), "ratchet-store-"));
      const macKey32 = randomBytes(32);
      const store = new FileRatchetStore(dir, macKey32);
      store.save("sess", createPersistedSession(newState()));
      const p = join(dir, "sess.json");
      const envelope = JSON.parse(readFileSync(p, "utf-8"));
      envelope.payload.state.skipped = skipped;
      envelope.mac_b64 = macV2(macKey32, "sess", envelope.payload);
      writeFileSync(p, JSON.stringify(envelope), "utf-8");
      return { dir, store };
    }
    const keyId = (n: number) => `${bytesToBase64(randomBytes(32))}:${n}`;
    const mk = () => Array.from(randomBytes(32));

    it("loads skipped keys written by the ratchet", () => {
      const dir = mkdtempSync(join(tmpdir(), "ratchet-store-"));
      try {
        const root = randomBytes(32);
        const aliceDh = generateX25519Keypair();
        const bobDh = generateX25519Keypair();
        let alice = ratchetInit({ rk32: root, selfDh: aliceDh, remoteDhPub32: bobDh.pub32, sendingFirst: true });
        let bob = ratchetInit({ rk32: root, selfDh: bobDh, remoteDhPub32: aliceDh.pub32, sendingFirst: false });
        const sent = [];
        for (let i = 0; i < 4; i++) {
          const r = ratchetEncrypt({
            state: alice,
            plaintext: encode(`m${i}`),
            sender_device_id: "alice",
            recipient_device_id: "bob",
          });
          alice = r.state;
          sent.push(r);
        }
        // Decrypting the 4th message first makes Bob store keys for messages 0..2.
        bob = ratchetDecrypt({
          state: bob,
          header: sent[3]!.header,
          ciphertext_b64: sent[3]!.ciphertext_b64,
        }).state;
        expect(bob.skipped.size).toBe(3);

        const store = new FileRatchetStore(dir, randomBytes(32));
        store.save("bob", createPersistedSession(bob));
        expect(store.load("bob")!.state.skipped.size).toBe(3);
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    });

    it("accepts exactly MAX_SKIPPED_KEYS entries", () => {
      const entries = Array.from({ length: MAX_SKIPPED_KEYS }, (_, i) => [keyId(i), mk()]);
      const { dir, store } = storeWithSkipped(entries);
      try {
        expect(store.load("sess")!.state.skipped.size).toBe(MAX_SKIPPED_KEYS);
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    });

    it("rejects more than MAX_SKIPPED_KEYS entries", () => {
      const entries = Array.from({ length: MAX_SKIPPED_KEYS + 1 }, (_, i) => [keyId(i), mk()]);
      const { dir, store } = storeWithSkipped(entries);
      try {
        expect(() => store.load("sess")).toThrow(/state\.skipped \(too many entries\)/);
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    });

    it("rejects malformed skipped-key IDs", () => {
      for (const bad of ["", "abc:1", `${bytesToBase64(randomBytes(32))}`, `${bytesToBase64(randomBytes(32))}:-1`,
                         `${bytesToBase64(randomBytes(32))}:01`, `${bytesToBase64(randomBytes(16))}:1`]) {
        const { dir, store } = storeWithSkipped([[bad, mk()]]);
        try {
          expect(() => store.load("sess"), bad).toThrow(/state\.skipped\[0\]\[0\]/);
        } finally {
          rmSync(dir, { recursive: true, force: true });
        }
      }
    });

    it("rejects duplicate skipped-key IDs", () => {
      const id = keyId(7);
      const { dir, store } = storeWithSkipped([[id, mk()], [id, mk()]]);
      try {
        expect(() => store.load("sess")).toThrow(/state\.skipped\[1\]\[0\] \(duplicate\)/);
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    });
  });
});

import { describe, it, expect, vi } from "vitest";
import { mkdtempSync, rmSync, readFileSync, writeFileSync, copyFileSync, unlinkSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { FileRatchetStore } from "./file-store.js";
import { ratchetEncrypt, ratchetDecrypt } from "./ratchet.js";
import { createPersistedSession } from "./session-store.js";
import { randomBytes } from "@noble/ciphers/utils.js";
import { sessionPair } from "../test-fixtures.js";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToBase64 } from "../encoding/base64.js";
import { MAX_SKIPPED_KEYS } from "../crypto/limits.js";
import { ReplayDetectedError, SessionNotFoundError } from "../errors.js";

function encode(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

/** MAC exactly as FileRatchetStore writes it (envelope v2, bound to the session ID). */
function macV2(key: Uint8Array, sessionId: string, payload: unknown): string {
  const input = encode(`moretag-crypto/file-store/session/v2\0${sessionId}\0${JSON.stringify(payload)}`);
  return bytesToBase64(hmac(sha256, key, input));
}

function newState() {
  return sessionPair().alice;
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

      const { alice: aliceState, bob: bobState } = sessionPair();

      store.save("alice->bob", createPersistedSession(aliceState));
      store.save("bob->alice", createPersistedSession(bobState));

      const { header, ciphertext_b64 } = ratchetEncrypt({
        state: aliceState,
        plaintext: encode("hi"),
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
      ).toThrow(ReplayDetectedError);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("transact on a missing id is SessionNotFoundError and never calls fn", () => {
    const dir = mkdtempSync(join(tmpdir(), "ratchet-store-"));
    try {
      const store = new FileRatchetStore(dir, randomBytes(32));
      const fn = vi.fn((current) => current);
      expect(() => store.transact("missing", fn)).toThrow(SessionNotFoundError);
      expect(fn).not.toHaveBeenCalled();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("detects simple rollback via version counter", () => {
    const dir = mkdtempSync(join(tmpdir(), "ratchet-store-"));
    try {
      const store = new FileRatchetStore(dir, randomBytes(32));
      const state = newState();

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

      const state = newState();

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
      const state = newState();

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
      const state = newState();

      store.save("sess", createPersistedSession(state));
      const p = join(dir, "sess.json");
      const raw = readFileSync(p, "utf-8");
      const parsed = JSON.parse(raw);
      parsed.payload.state.rk32_b64 = bytesToBase64(randomBytes(31));
      parsed.mac_b64 = macV2(macKey32, "sess", parsed.payload);
      writeFileSync(p, JSON.stringify(parsed), "utf-8");

      expect(() => store.load("sess")).toThrow(/^Corrupt session state: state\.rk32_b64$/);
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

  it("rejects a file without an envelope version (the 2.1.x format)", () => {
    const dir = mkdtempSync(join(tmpdir(), "ratchet-store-"));
    try {
      const macKey32 = randomBytes(32);
      const store = new FileRatchetStore(dir, macKey32);
      store.save("sess", createPersistedSession(newState()));
      const p = join(dir, "sess.json");
      const { payload } = JSON.parse(readFileSync(p, "utf-8"));
      const mac_b64 = bytesToBase64(hmac(sha256, macKey32, encode(JSON.stringify(payload))));
      writeFileSync(p, JSON.stringify({ payload, mac_b64 }), "utf-8");

      expect(() => store.load("sess")).toThrow(/unsupported envelope version/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("rejects unknown envelope versions", () => {
    const dir = mkdtempSync(join(tmpdir(), "ratchet-store-"));
    try {
      const store = new FileRatchetStore(dir, randomBytes(32));
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
    function setup() {
      const dir = mkdtempSync(join(tmpdir(), "ratchet-store-"));
      const macKey32 = randomBytes(32);
      const store = new FileRatchetStore(dir, macKey32);
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

    it("rejects garbage and the 2.1.x plain-number format", () => {
      const { dir, store, state } = setup();
      try {
        store.save("sess", { version: 2, state });
        const p = join(dir, "sess.ver");

        writeFileSync(p, "not json", "utf-8");
        expect(() => store.load("sess")).toThrow(/Invalid rollback counter file/);
        expect(() => store.save("sess", { version: 3, state })).toThrow(/Invalid rollback counter file/);

        writeFileSync(p, "0", "utf-8");
        expect(() => store.load("sess")).toThrow(/Invalid rollback counter file/);
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
    const mk = () => bytesToBase64(randomBytes(32));

    it("loads skipped keys written by the ratchet", () => {
      const dir = mkdtempSync(join(tmpdir(), "ratchet-store-"));
      try {
        let { alice, bob } = sessionPair();
        const sent = [];
        for (let i = 0; i < 4; i++) {
          const r = ratchetEncrypt({
            state: alice,
            plaintext: encode(`m${i}`),
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

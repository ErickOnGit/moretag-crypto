import { describe, it, expect } from "vitest";
import { mkdtempSync, rmSync, readFileSync, writeFileSync } from "fs";
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

function encode(str: string): Uint8Array {
  return new TextEncoder().encode(str);
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
      const payloadBytes = new TextEncoder().encode(JSON.stringify(parsed.payload));
      parsed.mac_b64 = bytesToBase64(hmac(sha256, macKey32, payloadBytes));
      writeFileSync(p, JSON.stringify(parsed), "utf-8");

      expect(() => store.load("sess")).toThrow(/Corrupt session state: state\.rk32/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

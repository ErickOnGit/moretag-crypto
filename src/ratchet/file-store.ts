import {
  readFileSync,
  writeFileSync,
  mkdirSync,
  renameSync,
  existsSync,
  openSync,
  closeSync,
  fsyncSync,
  unlinkSync,
} from "fs";
import { dirname, join } from "path";
import type { PersistedSession, RatchetSessionStore } from "./session-store.js";
import { SessionNotFoundError, StoreIoError } from "../errors.js";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToBase64, decodeStrictBase64 } from "../encoding/base64.js";
import { assertBoundedString } from "../crypto/validation.js";
import { MAX_SESSION_ID_BYTES } from "../crypto/limits.js";
import {
  deserializePersistedSessionV2,
  serializePersistedSessionV2,
  type SerializedPersistedSessionV2,
} from "./serialization.js";

/** Current on-disk envelope format: MAC is bound to the session ID. */
const ENVELOPE_VERSION = 2;
/** Domain-separation prefix for session-file MACs (envelope v2). */
const SESSION_MAC_CONTEXT = "moretag-crypto/file-store/session/v2";
/** Domain-separation prefix for rollback-counter MACs. */
const COUNTER_MAC_CONTEXT = "moretag-crypto/file-store/counter/v2";

interface SessionEnvelope {
  v?: unknown;
  payload: unknown;
  mac_b64: string;
}

/**
 * Runs file-system calls and turns any failure into {@link StoreIoError}: Node's
 * messages hold the path, and so the session id. Only fs calls go through here,
 * never the library's own checks or a transact callback.
 */
function io<T>(fn: () => T): T {
  try {
    return fn();
  } catch (err) {
    const fsCode = (err as { code?: unknown } | null)?.code;
    throw new StoreIoError(typeof fsCode === "string" ? fsCode : undefined);
  }
}

function atomicWrite(filePath: string, data: string): void {
  const dir = dirname(filePath);
  const tmp = join(dir, `.tmp-${Date.now()}-${Math.random().toString(16).slice(2)}`);
  io(() => {
    mkdirSync(dir, { recursive: true });
    const fd = openSync(tmp, "wx", 0o600);
    try {
      writeFileSync(fd, data, { encoding: "utf-8" });
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    renameSync(tmp, filePath);
  });
  // Best-effort directory fsync for durability.
  try {
    const dfd = openSync(dir, "r");
    try {
      fsyncSync(dfd);
    } finally {
      closeSync(dfd);
    }
  } catch {
    // ignore
  }
}

function assertSafeSessionId(sessionId: string): void {
  assertBoundedString("sessionId", sessionId, MAX_SESSION_ID_BYTES);
  if (sessionId.includes("/") || sessionId.includes("\\") || sessionId.includes("\0")) {
    throw new TypeError("sessionId contains invalid path separator characters");
  }
  if (sessionId === "." || sessionId === "..") {
    throw new TypeError("sessionId must not be '.' or '..'");
  }
}

function isSessionEnvelope(v: unknown): v is SessionEnvelope {
  return (
    typeof v === "object" &&
    v !== null &&
    !Array.isArray(v) &&
    "mac_b64" in v &&
    typeof v.mac_b64 === "string" &&
    "payload" in v
  );
}

export class FileRatchetStore implements RatchetSessionStore {
  constructor(
    private baseDir: string,
    private macKey32: Uint8Array
  ) {
    if (!(macKey32 instanceof Uint8Array) || macKey32.byteLength !== 32) {
      throw new TypeError("macKey32 must be a 32-byte Uint8Array");
    }
  }

  private pathFor(sessionId: string): string {
    assertSafeSessionId(sessionId);
    return join(this.baseDir, `${sessionId}.json`);
  }

  private versionPath(sessionId: string): string {
    assertSafeSessionId(sessionId);
    return join(this.baseDir, `${sessionId}.ver`);
  }

  private lockPath(sessionId: string): string {
    assertSafeSessionId(sessionId);
    return join(this.baseDir, `${sessionId}.lock`);
  }

  /**
   * Runs fn while holding `<sessionId>.lock`, created exclusively. A lock that is
   * already there is {@link StoreIoError} with `fsCode` `EEXIST`: another process
   * holds the session, or a crash inside load, save or transact left the lock
   * behind. There is no wait and no age check; recovery is SPEC §14's.
   */
  private withLock<T>(sessionId: string, fn: () => T): T {
    const lock = this.lockPath(sessionId);
    const fd = io(() => {
      mkdirSync(dirname(lock), { recursive: true });
      return openSync(lock, "wx", 0o600);
    });
    try {
      return fn();
    } finally {
      try {
        io(() => closeSync(fd));
      } finally {
        try {
          unlinkSync(lock);
        } catch {
          // ignore
        }
      }
    }
  }

  private counterMacInput(sessionId: string, version: number): Uint8Array {
    return new TextEncoder().encode(`${COUNTER_MAC_CONTEXT}\0${sessionId}\0${version}`);
  }

  /**
   * Reads the rollback counter. Returns undefined only when the file doesn't exist; a file that
   * exists but is malformed or fails its MAC throws, so it can't be edited to disable the check.
   */
  private readCounter(sessionId: string): number | undefined {
    const p = this.versionPath(sessionId);
    if (!existsSync(p)) return undefined;

    const text = io(() => readFileSync(p, "utf-8"));
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      throw new Error("Invalid rollback counter file");
    }

    if (
      typeof parsed !== "object" ||
      parsed === null ||
      Array.isArray(parsed) ||
      !("v" in parsed) ||
      parsed.v !== ENVELOPE_VERSION ||
      !("version" in parsed) ||
      typeof parsed.version !== "number" ||
      !Number.isInteger(parsed.version) ||
      parsed.version < 0 ||
      !("mac_b64" in parsed) ||
      typeof parsed.mac_b64 !== "string"
    ) {
      throw new Error("Invalid rollback counter file");
    }

    this.verifyMac(
      "rollback counter",
      parsed.mac_b64,
      this.counterMacInput(sessionId, parsed.version)
    );
    return parsed.version;
  }

  private writeCounter(sessionId: string, version: number): void {
    const p = this.versionPath(sessionId);
    atomicWrite(
      p,
      JSON.stringify({
        v: ENVELOPE_VERSION,
        version,
        mac_b64: this.computeMac(this.counterMacInput(sessionId, version)),
      })
    );
  }

  /**
   * MAC input for a session file. Binding the session ID means a validly signed file for one
   * session cannot be copied over another session's file. Session IDs never contain NUL
   * (enforced by assertSafeSessionId), so the encoding is unambiguous.
   */
  private sessionMacInput(sessionId: string, payloadJson: string): Uint8Array {
    return new TextEncoder().encode(`${SESSION_MAC_CONTEXT}\0${sessionId}\0${payloadJson}`);
  }

  private computeMac(bytes: Uint8Array): string {
    const mac = hmac(sha256, this.macKey32, bytes);
    return bytesToBase64(mac);
  }

  private verifyMac(label: string, mac_b64: string, bytes: Uint8Array): void {
    const expected = decodeStrictBase64(label, mac_b64);
    const actual = hmac(sha256, this.macKey32, bytes);
    if (expected.byteLength !== actual.byteLength) {
      throw new Error(
        `Invalid ${label}: MAC length mismatch (expected ${actual.byteLength}, got ${expected.byteLength})`
      );
    }
    let diff = 0;
    for (let i = 0; i < actual.length; i++) diff |= expected[i]! ^ actual[i]!;
    if (diff !== 0) throw new Error(`Invalid ${label}: MAC verification failed`);
  }

  private loadUnlocked(sessionId: string): PersistedSession | undefined {
    const file = this.pathFor(sessionId);
    if (!existsSync(file)) return undefined;

    const data = io(() => readFileSync(file, "utf-8"));
    let parsed: unknown;
    try {
      parsed = JSON.parse(data);
    } catch {
      // JSON.parse's own message quotes the file's contents.
      throw new Error("Invalid session file: not JSON");
    }

    if (!isSessionEnvelope(parsed)) {
      throw new Error("Invalid session file: missing mac_b64");
    }
    if (parsed.v !== ENVELOPE_VERSION) {
      throw new Error("Invalid session file: unsupported envelope version");
    }
    const payloadJson = JSON.stringify(parsed.payload);
    this.verifyMac("mac_b64", parsed.mac_b64, this.sessionMacInput(sessionId, payloadJson));
    // The payload is the public serialized form; its deserializer checks every field.
    const record = deserializePersistedSessionV2(parsed.payload as SerializedPersistedSessionV2);

    const counter = this.readCounter(sessionId);
    if (counter === undefined) {
      // saveUnlocked always leaves a counter behind once a session file exists, so a missing
      // one means it was deleted — which would otherwise switch off rollback detection.
      throw new Error("Rollback counter missing for session");
    }
    if (record.version < counter) {
      throw new Error("Rollback detected: session version behind persisted counter");
    }
    return record;
  }

  load(sessionId: string): PersistedSession | undefined {
    return this.withLock(sessionId, () => this.loadUnlocked(sessionId));
  }

  private saveUnlocked(sessionId: string, record: PersistedSession): void {
    const file = this.pathFor(sessionId);
    const counter = this.readCounter(sessionId);
    if (counter !== undefined && record.version < counter) {
      throw new Error("Refusing to save stale session version (possible rollback)");
    }

    const payloadObj = serializePersistedSessionV2(record);
    const payloadJson = JSON.stringify(payloadObj);

    const toWrite = JSON.stringify({
      v: ENVELOPE_VERSION,
      payload: payloadObj,
      mac_b64: this.computeMac(this.sessionMacInput(sessionId, payloadJson)),
    });

    // Write order keeps a crash from leaving a session unloadable. For a new session, write the
    // counter first: a crash before the session file lands leaves no session (load returns
    // undefined), never a session without a counter. For an existing session, write the session
    // first: a crash before the counter lands leaves the counter behind the session, which loads.
    if (!existsSync(file)) {
      this.writeCounter(sessionId, record.version);
      atomicWrite(file, toWrite);
    } else {
      atomicWrite(file, toWrite);
      this.writeCounter(sessionId, record.version);
    }
  }

  save(sessionId: string, record: PersistedSession): void {
    return this.withLock(sessionId, () => this.saveUnlocked(sessionId, record));
  }

  transact(sessionId: string, fn: (current: PersistedSession) => PersistedSession): PersistedSession {
    return this.withLock(sessionId, () => {
      const current = this.loadUnlocked(sessionId);
      if (!current) throw new SessionNotFoundError();
      const next = fn(current);
      this.saveUnlocked(sessionId, next);
      return next;
    });
  }
}

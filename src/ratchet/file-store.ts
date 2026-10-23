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
import { cloneRatchetState } from "./session-store.js";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToBase64, decodeStrictBase64 } from "../encoding/base64.js";
import { assertBoundedString } from "../crypto/validation.js";
import { MAX_SESSION_ID_BYTES, MAX_SKIPPED_KEYS } from "../crypto/limits.js";

/** Current on-disk envelope format: MAC is bound to the session ID. */
const ENVELOPE_VERSION = 2;
/** Domain-separation prefix for session-file MACs (envelope v2). */
const SESSION_MAC_CONTEXT = "moretag-crypto/file-store/session/v2";
/** Domain-separation prefix for rollback-counter MACs. */
const COUNTER_MAC_CONTEXT = "moretag-crypto/file-store/counter/v2";

export interface FileRatchetStoreOptions {
  /**
   * Also accept files in the 2.1.x format: session files whose MAC covers only the payload
   * and is not bound to the session ID, and unsigned plain-number rollback counters. Meant for
   * a one-time migration: load and re-save each session with this enabled, which rewrites both
   * files in the current format, then turn it off. Default: false.
   */
  allowLegacyFormat?: boolean;
}

interface SessionEnvelope {
  v?: unknown;
  payload: unknown;
  mac_b64: string;
}

interface PersistedStateShape {
  version: number;
  state: {
    version: 1;
    rk32: number[];
    ck_s32?: number[];
    ck_r32?: number[];
    ns: number;
    nr: number;
    pn: number;
    dh_self: { priv32: number[]; pub32: number[] };
    dh_remote_pub32: number[];
    skipped: Array<[string, number[]]>;
  };
}

function atomicWrite(filePath: string, data: string): void {
  const dir = dirname(filePath);
  mkdirSync(dir, { recursive: true });
  const tmp = join(dir, `.tmp-${Date.now()}-${Math.random().toString(16).slice(2)}`);
  const fd = openSync(tmp, "wx", 0o600);
  try {
    writeFileSync(fd, data, { encoding: "utf-8" });
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  renameSync(tmp, filePath);
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

/**
 * Skipped-key IDs are `${base64(32-byte DH public key)}:${message number}`, as produced by the
 * ratchet. Anything else can never match an incoming message and only takes up space.
 */
const SKIPPED_KEY_ID = /^[A-Za-z0-9+/]{43}=:(0|[1-9][0-9]{0,15})$/;

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
    private macKey32: Uint8Array,
    private opts: FileRatchetStoreOptions = {}
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

  private withLock<T>(sessionId: string, fn: () => T): T {
    const lock = this.lockPath(sessionId);
    mkdirSync(dirname(lock), { recursive: true });
    const fd = openSync(lock, "wx", 0o600);
    try {
      return fn();
    } finally {
      try {
        closeSync(fd);
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

    let parsed: unknown;
    try {
      parsed = JSON.parse(readFileSync(p, "utf-8"));
    } catch {
      throw new Error("Invalid rollback counter file");
    }

    if (typeof parsed === "number") {
      // 2.1.x wrote the counter as a bare, unsigned number.
      if (!this.opts.allowLegacyFormat) {
        throw new Error(
          "Legacy rollback counter format (unsigned); " +
            "construct the store with { allowLegacyFormat: true } once to migrate it"
        );
      }
      if (!Number.isInteger(parsed) || parsed < 0) throw new Error("Invalid rollback counter file");
      return parsed;
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

  private encodeRecord(record: PersistedSession): { version: number; state: any } {
    return {
      version: record.version,
      state: {
        version: record.state.version,
        rk32: Array.from(record.state.rk32),
        ck_s32: record.state.ck_s32 ? Array.from(record.state.ck_s32) : undefined,
        ck_r32: record.state.ck_r32 ? Array.from(record.state.ck_r32) : undefined,
        ns: record.state.ns,
        nr: record.state.nr,
        pn: record.state.pn,
        dh_self: {
          priv32: Array.from(record.state.dh_self.priv32),
          pub32: Array.from(record.state.dh_self.pub32),
        },
        dh_remote_pub32: Array.from(record.state.dh_remote_pub32),
        skipped: Array.from(record.state.skipped.entries()).map(([k, v]) => [
          k,
          Array.from(v),
        ]),
      },
    };
  }

  private validatePersistedStateShape(parsed: unknown): asserts parsed is PersistedStateShape {
    const fail = (field: string): never => {
      throw new Error(`Corrupt session state: ${field}`);
    };
    const isPlainObject = (v: unknown): v is Record<string, unknown> =>
      typeof v === "object" && v !== null && !Array.isArray(v);
    const isNonNegativeInteger = (v: unknown): v is number =>
      typeof v === "number" && Number.isInteger(v) && v >= 0;
    const isSerializedByteArray32 = (v: unknown): v is number[] =>
      Array.isArray(v) &&
      v.length === 32 &&
      v.every((n) => typeof n === "number" && Number.isInteger(n) && n >= 0 && n <= 255);

    if (!isPlainObject(parsed)) fail("root");
    const root = parsed as Record<string, unknown>;
    if (!isNonNegativeInteger(root.version)) fail("version");
    if (!isPlainObject(root.state)) fail("state");

    const state = root.state as Record<string, unknown>;
    if (state.version !== 1) fail("state.version");
    if (!isSerializedByteArray32(state.rk32)) fail("state.rk32");
    if (state.ck_s32 !== undefined && !isSerializedByteArray32(state.ck_s32)) fail("state.ck_s32");
    if (state.ck_r32 !== undefined && !isSerializedByteArray32(state.ck_r32)) fail("state.ck_r32");
    if (!isNonNegativeInteger(state.ns)) fail("state.ns");
    if (!isNonNegativeInteger(state.nr)) fail("state.nr");
    if (!isNonNegativeInteger(state.pn)) fail("state.pn");

    if (!isPlainObject(state.dh_self)) fail("state.dh_self");
    const dhSelf = state.dh_self as Record<string, unknown>;
    if (!isSerializedByteArray32(dhSelf.priv32)) fail("state.dh_self.priv32");
    if (!isSerializedByteArray32(dhSelf.pub32)) fail("state.dh_self.pub32");
    if (!isSerializedByteArray32(state.dh_remote_pub32)) fail("state.dh_remote_pub32");

    if (!Array.isArray(state.skipped)) fail("state.skipped");
    const skipped = state.skipped as unknown[];
    // The ratchet never holds more than MAX_SKIPPED_KEYS, so a larger list wasn't written by it.
    if (skipped.length > MAX_SKIPPED_KEYS) fail("state.skipped (too many entries)");
    const seen = new Set<string>();
    for (let i = 0; i < skipped.length; i++) {
      const entry = skipped[i];
      if (!Array.isArray(entry) || entry.length !== 2) fail(`state.skipped[${i}]`);
      const [key, value] = entry as [unknown, unknown];
      if (typeof key !== "string" || !SKIPPED_KEY_ID.test(key)) fail(`state.skipped[${i}][0]`);
      // Duplicates would be silently collapsed by the Map on load.
      if (seen.has(key as string)) fail(`state.skipped[${i}][0] (duplicate)`);
      seen.add(key as string);
      if (!isSerializedByteArray32(value)) fail(`state.skipped[${i}][1]`);
    }
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

    const data = readFileSync(file, "utf-8");
    const parsed: unknown = JSON.parse(data);

    if (!isSessionEnvelope(parsed)) {
      throw new Error("Invalid session file: missing mac_b64");
    }

    const payloadJson = JSON.stringify(parsed.payload);
    if (parsed.v === ENVELOPE_VERSION) {
      this.verifyMac("mac_b64", parsed.mac_b64, this.sessionMacInput(sessionId, payloadJson));
    } else if (parsed.v === undefined) {
      if (!this.opts.allowLegacyFormat) {
        throw new Error(
          "Legacy session file format (MAC not bound to session ID); " +
            "construct the store with { allowLegacyFormat: true } once to migrate it"
        );
      }
      this.verifyMac("mac_b64", parsed.mac_b64, new TextEncoder().encode(payloadJson));
    } else {
      throw new Error("Invalid session file: unsupported envelope version");
    }
    this.validatePersistedStateShape(parsed.payload);
    const payload = parsed.payload;

    const counter = this.readCounter(sessionId);
    if (counter === undefined && parsed.v === ENVELOPE_VERSION) {
      // saveUnlocked always leaves a counter behind once a session file exists, so a missing
      // one means it was deleted — which would otherwise switch off rollback detection.
      throw new Error("Rollback counter missing for session");
    }
    if (counter !== undefined && payload.version < counter) {
      throw new Error("Rollback detected: session version behind persisted counter");
    }

    return {
      version: payload.version,
      state: cloneRatchetState({
        version: payload.state.version,
        rk32: Uint8Array.from(payload.state.rk32),
        ck_s32: payload.state.ck_s32 ? Uint8Array.from(payload.state.ck_s32) : undefined,
        ck_r32: payload.state.ck_r32 ? Uint8Array.from(payload.state.ck_r32) : undefined,
        ns: payload.state.ns,
        nr: payload.state.nr,
        pn: payload.state.pn,
        dh_self: {
          priv32: Uint8Array.from(payload.state.dh_self.priv32),
          pub32: Uint8Array.from(payload.state.dh_self.pub32),
        },
        dh_remote_pub32: Uint8Array.from(payload.state.dh_remote_pub32),
        skipped: new Map(
          payload.state.skipped.map(([k, v]) => [k, Uint8Array.from(v)] as const)
        ),
      }),
    };
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

    const payloadObj = this.encodeRecord(record);
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
      if (!current) throw new Error("Session not found");
      const next = fn(current);
      this.saveUnlocked(sessionId, next);
      return next;
    });
  }
}

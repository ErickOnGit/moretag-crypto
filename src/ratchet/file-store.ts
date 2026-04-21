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
import { MAX_SESSION_ID_BYTES } from "../crypto/limits.js";

interface SessionEnvelope {
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

  private readCounter(sessionId: string): number | undefined {
    const p = this.versionPath(sessionId);
    if (!existsSync(p)) return undefined;
    try {
      const v = Number(readFileSync(p, "utf-8"));
      return Number.isFinite(v) ? v : undefined;
    } catch {
      return undefined;
    }
  }

  private writeCounter(sessionId: string, version: number): void {
    const p = this.versionPath(sessionId);
    atomicWrite(p, String(version));
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
    for (let i = 0; i < skipped.length; i++) {
      const entry = skipped[i];
      if (!Array.isArray(entry) || entry.length !== 2) fail(`state.skipped[${i}]`);
      const [key, value] = entry as [unknown, unknown];
      if (typeof key !== "string") fail(`state.skipped[${i}][0]`);
      if (!isSerializedByteArray32(value)) fail(`state.skipped[${i}][1]`);
    }
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

    const bytes = new TextEncoder().encode(JSON.stringify(parsed.payload));
    this.verifyMac("mac_b64", parsed.mac_b64, bytes);
    this.validatePersistedStateShape(parsed.payload);
    const payload = parsed.payload;

    const counter = this.readCounter(sessionId);
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
      payload: payloadObj,
      mac_b64: this.computeMac(new TextEncoder().encode(payloadJson)),
    });

    atomicWrite(file, toWrite);
    this.writeCounter(sessionId, record.version);
  }

  save(sessionId: string, record: PersistedSession): void {
    return this.withLock(sessionId, () => this.saveUnlocked(sessionId, record));
  }

  transact(sessionId: string, fn: (current: PersistedSession) => PersistedSession): PersistedSession {
    return this.withLock(sessionId, () => {
      const current = this.loadUnlocked(sessionId);
      if (!current) throw new Error(`Session not found: ${sessionId}`);
      const next = fn(current);
      this.saveUnlocked(sessionId, next);
      return next;
    });
  }
}

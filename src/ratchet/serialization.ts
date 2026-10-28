/**
 * JSON-safe (de)serialization for Double Ratchet sessions.
 *
 * RatchetState holds Uint8Array keys and a Map of skipped message keys, neither
 * of which survives JSON.stringify. Native consumers (e.g. the mobile app's
 * AsyncStorage-backed store) need a plain, JSON-safe shape — base64 for bytes,
 * an entries array for the Map — without owning the conversion logic. These
 * helpers are the canonical, reusable form of what FileRatchetStore does inline.
 */

import type { RatchetState } from "./ratchet.js";
import type { PersistedSession } from "./session-store.js";
import { bytesToBase64, decodeStrictBase64 } from "../encoding/base64.js";
import { MAX_SKIPPED_KEYS } from "../crypto/limits.js";
import { SKIPPED_KEY_ID } from "./skipped-id.js";

/** JSON-safe representation of a RatchetState. `v` is the serialization format version. */
export interface SerializedRatchetStateV1 {
  v: 1;
  rk32_b64: string;
  ck_s32_b64: string | null;
  ck_r32_b64: string | null;
  ns: number;
  nr: number;
  pn: number;
  dh_self: { priv32_b64: string; pub32_b64: string };
  dh_remote_pub32_b64: string;
  /** Skipped message keys: [skippedKeyId, messageKey_b64]. */
  skipped: Array<[string, string]>;
}

/** JSON-safe representation of a PersistedSession (optimistic store counter + state). */
export interface SerializedPersistedSessionV1 {
  v: 1;
  version: number;
  state: SerializedRatchetStateV1;
}

export function serializeRatchetStateV1(state: RatchetState): SerializedRatchetStateV1 {
  return {
    v: 1,
    rk32_b64: bytesToBase64(state.rk32),
    ck_s32_b64: state.ck_s32 ? bytesToBase64(state.ck_s32) : null,
    ck_r32_b64: state.ck_r32 ? bytesToBase64(state.ck_r32) : null,
    ns: state.ns,
    nr: state.nr,
    pn: state.pn,
    dh_self: {
      priv32_b64: bytesToBase64(state.dh_self.priv32),
      pub32_b64: bytesToBase64(state.dh_self.pub32),
    },
    dh_remote_pub32_b64: bytesToBase64(state.dh_remote_pub32),
    skipped: Array.from(state.skipped.entries()).map(([id, mk]) => [
      id,
      bytesToBase64(mk),
    ]),
  };
}

/** Every refusal names the field, never the stored value. */
function corrupt(field: string): never {
  throw new TypeError(`Corrupt session state: ${field}`);
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function counter(field: string, v: unknown): number {
  if (typeof v !== "number" || !Number.isSafeInteger(v) || v < 0) corrupt(field);
  return v;
}

function key32(field: string, v: unknown): Uint8Array {
  if (typeof v !== "string") corrupt(field);
  let bytes: Uint8Array;
  try {
    bytes = decodeStrictBase64(field, v);
  } catch {
    corrupt(field);
  }
  if (bytes.byteLength !== 32) corrupt(field);
  return bytes;
}

/** A chain key is null (no chain yet) or exactly 32 bytes; "" is not null. */
function chainKey32(field: string, v: unknown): Uint8Array | undefined {
  return v === null ? undefined : key32(field, v);
}

function readState(serialized: unknown, at: string): RatchetState {
  if (!isPlainObject(serialized)) corrupt(at === "" ? "root" : at.slice(0, -1));
  const s = serialized;
  if (s.v !== 1) corrupt(`${at}v`);
  const rk32 = key32(`${at}rk32_b64`, s.rk32_b64);
  const ck_s32 = chainKey32(`${at}ck_s32_b64`, s.ck_s32_b64);
  const ck_r32 = chainKey32(`${at}ck_r32_b64`, s.ck_r32_b64);
  const ns = counter(`${at}ns`, s.ns);
  const nr = counter(`${at}nr`, s.nr);
  const pn = counter(`${at}pn`, s.pn);
  if (!isPlainObject(s.dh_self)) corrupt(`${at}dh_self`);
  const dh_self = {
    priv32: key32(`${at}dh_self.priv32_b64`, s.dh_self.priv32_b64),
    pub32: key32(`${at}dh_self.pub32_b64`, s.dh_self.pub32_b64),
  };
  const dh_remote_pub32 = key32(`${at}dh_remote_pub32_b64`, s.dh_remote_pub32_b64);

  if (!Array.isArray(s.skipped)) corrupt(`${at}skipped`);
  // The ratchet never holds more than MAX_SKIPPED_KEYS, so a longer list wasn't written by it.
  if (s.skipped.length > MAX_SKIPPED_KEYS) corrupt(`${at}skipped (too many entries)`);
  const skipped = new Map<string, Uint8Array>();
  s.skipped.forEach((entry: unknown, i: number) => {
    if (!Array.isArray(entry) || entry.length !== 2) corrupt(`${at}skipped[${i}]`);
    const [id, mk] = entry as [unknown, unknown];
    if (typeof id !== "string" || !SKIPPED_KEY_ID.test(id)) corrupt(`${at}skipped[${i}][0]`);
    // A Map would silently collapse duplicates.
    if (skipped.has(id)) corrupt(`${at}skipped[${i}][0] (duplicate)`);
    skipped.set(id, key32(`${at}skipped[${i}][1]`, mk));
  });

  return { version: 1, rk32, ck_s32, ck_r32, ns, nr, pn, dh_self, dh_remote_pub32, skipped };
}

/**
 * Rebuilds a RatchetState from its stored form. Stored state is untrusted input:
 * every field is checked (32-byte keys, chain keys null or 32 bytes, counters
 * non-negative safe integers, at most MAX_SKIPPED_KEYS skipped keys with ids in
 * the ratchet's grammar and no duplicates), and a refusal reads
 * "Corrupt session state: <field>" without the stored value.
 */
export function deserializeRatchetStateV1(serialized: SerializedRatchetStateV1): RatchetState {
  return readState(serialized, "");
}

export function serializePersistedSessionV1(
  record: PersistedSession
): SerializedPersistedSessionV1 {
  return {
    v: 1,
    version: record.version,
    state: serializeRatchetStateV1(record.state),
  };
}

/** Rebuilds a PersistedSession; checks its format version and counter, then the state. */
export function deserializePersistedSessionV1(
  serialized: SerializedPersistedSessionV1
): PersistedSession {
  const s: unknown = serialized;
  if (!isPlainObject(s)) corrupt("root");
  if (s.v !== 1) corrupt("v");
  const version = counter("version", s.version);
  return { version, state: readState(s.state, "state.") };
}

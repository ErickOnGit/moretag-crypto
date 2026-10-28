/**
 * JSON-safe (de)serialization for Double Ratchet sessions.
 *
 * RatchetState holds Uint8Array keys and a Map of skipped message keys, neither
 * of which survives JSON.stringify. Native consumers (e.g. the mobile app's
 * AsyncStorage-backed store) need a plain, JSON-safe shape — base64 for bytes,
 * an entries array for the Map — without owning the conversion logic. These
 * helpers are the canonical, reusable form of what FileRatchetStore does inline.
 */

import type { RatchetRole, RatchetState } from "./ratchet.js";
import type { PersistedSession } from "./session-store.js";
import { bytesToBase64, decodeStrictBase64 } from "../encoding/base64.js";
import { MAX_SKIPPED_KEYS } from "../crypto/limits.js";
import { ASSOCIATED_DATA_V2_LENGTH, parseAssociatedDataV2 } from "../crypto/ad.js";
import { isSkippedKeyId } from "./skipped-id.js";

/** JSON-safe representation of a RatchetState. `v` is the serialization format version. */
export interface SerializedRatchetStateV2 {
  v: 2;
  role: RatchetRole;
  /** The session's 164-byte associated data. */
  ad_b64: string;
  rk32_b64: string;
  ck_s32_b64: string | null;
  ck_r32_b64: string | null;
  ns: number;
  nr: number;
  pn: number;
  dh_self: { priv32_b64: string; pub32_b64: string };
  /** Null on a responder state before its first received message. */
  dh_remote_pub32_b64: string | null;
  /** Skipped message keys, oldest first: [skippedKeyId, messageKey_b64]. */
  skipped: Array<[string, string]>;
}

/** JSON-safe representation of a PersistedSession (optimistic store counter + state). */
export interface SerializedPersistedSessionV2 {
  v: 2;
  version: number;
  state: SerializedRatchetStateV2;
}

export function serializeRatchetStateV2(state: RatchetState): SerializedRatchetStateV2 {
  return {
    v: 2,
    role: state.role,
    ad_b64: bytesToBase64(state.ad),
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
    dh_remote_pub32_b64: state.dh_remote_pub32 ? bytesToBase64(state.dh_remote_pub32) : null,
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

function fixedBytes(field: string, v: unknown, length: number): Uint8Array {
  if (typeof v !== "string") corrupt(field);
  let bytes: Uint8Array;
  try {
    bytes = decodeStrictBase64(field, v);
  } catch {
    corrupt(field);
  }
  if (bytes.byteLength !== length) corrupt(field);
  return bytes;
}

function key32(field: string, v: unknown): Uint8Array {
  return fixedBytes(field, v, 32);
}

/** A chain key or the remote key is null (absent) or exactly 32 bytes; "" is not null. */
function optionalKey32(field: string, v: unknown): Uint8Array | undefined {
  return v === null ? undefined : key32(field, v);
}

function associatedData(field: string, v: unknown): Uint8Array {
  const ad = fixedBytes(field, v, ASSOCIATED_DATA_V2_LENGTH);
  try {
    parseAssociatedDataV2(ad);
  } catch {
    corrupt(field);
  }
  return ad;
}

function readState(serialized: unknown, at: string): RatchetState {
  if (!isPlainObject(serialized)) corrupt(at === "" ? "root" : at.slice(0, -1));
  const s = serialized;
  if (s.v !== 2) corrupt(`${at}v`);
  if (s.role !== "initiator" && s.role !== "responder") corrupt(`${at}role`);
  const role: RatchetRole = s.role;
  const ad = associatedData(`${at}ad_b64`, s.ad_b64);
  const rk32 = key32(`${at}rk32_b64`, s.rk32_b64);
  const ck_s32 = optionalKey32(`${at}ck_s32_b64`, s.ck_s32_b64);
  const ck_r32 = optionalKey32(`${at}ck_r32_b64`, s.ck_r32_b64);
  const ns = counter(`${at}ns`, s.ns);
  const nr = counter(`${at}nr`, s.nr);
  const pn = counter(`${at}pn`, s.pn);
  if (!isPlainObject(s.dh_self)) corrupt(`${at}dh_self`);
  const dh_self = {
    priv32: key32(`${at}dh_self.priv32_b64`, s.dh_self.priv32_b64),
    pub32: key32(`${at}dh_self.pub32_b64`, s.dh_self.pub32_b64),
  };
  const dh_remote_pub32 = optionalKey32(`${at}dh_remote_pub32_b64`, s.dh_remote_pub32_b64);

  if (!Array.isArray(s.skipped)) corrupt(`${at}skipped`);
  // The ratchet never holds more than MAX_SKIPPED_KEYS, so a longer list wasn't written by it.
  if (s.skipped.length > MAX_SKIPPED_KEYS) corrupt(`${at}skipped (too many entries)`);
  const skipped = new Map<string, Uint8Array>();
  s.skipped.forEach((entry: unknown, i: number) => {
    if (!Array.isArray(entry) || entry.length !== 2) corrupt(`${at}skipped[${i}]`);
    const [id, mk] = entry as [unknown, unknown];
    if (!isSkippedKeyId(id)) corrupt(`${at}skipped[${i}][0]`);
    // A Map would silently collapse duplicates.
    if (skipped.has(id)) corrupt(`${at}skipped[${i}][0] (duplicate)`);
    skipped.set(id, key32(`${at}skipped[${i}][1]`, mk));
  });

  return { version: 2, role, ad, rk32, ck_s32, ck_r32, ns, nr, pn, dh_self, dh_remote_pub32, skipped };
}

/**
 * Rebuilds a RatchetState from its stored form. Stored state is untrusted input:
 * every field is checked (role, a well-formed 164-byte AD, 32-byte keys, chain
 * keys and the remote key null or 32 bytes, counters non-negative safe integers,
 * at most MAX_SKIPPED_KEYS skipped keys with ids in the ratchet's grammar (the
 * canonical base64 of a 32-byte key, ":", a safe integer) and no
 * duplicates), and a refusal reads "Corrupt session state: <field>" without the
 * stored value.
 */
export function deserializeRatchetStateV2(serialized: SerializedRatchetStateV2): RatchetState {
  return readState(serialized, "");
}

export function serializePersistedSessionV2(
  record: PersistedSession
): SerializedPersistedSessionV2 {
  return {
    v: 2,
    version: record.version,
    state: serializeRatchetStateV2(record.state),
  };
}

/** Rebuilds a PersistedSession; checks its format version and counter, then the state. */
export function deserializePersistedSessionV2(
  serialized: SerializedPersistedSessionV2
): PersistedSession {
  const s: unknown = serialized;
  if (!isPlainObject(s)) corrupt("root");
  if (s.v !== 2) corrupt("v");
  const version = counter("version", s.version);
  return { version, state: readState(s.state, "state.") };
}

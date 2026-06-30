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

export function deserializeRatchetStateV1(serialized: SerializedRatchetStateV1): RatchetState {
  if (serialized.v !== 1) {
    throw new TypeError(
      `Unsupported serialized ratchet state version: ${(serialized as { v: unknown }).v}`
    );
  }

  return {
    version: 1,
    rk32: decodeStrictBase64("rk32_b64", serialized.rk32_b64),
    ck_s32: serialized.ck_s32_b64
      ? decodeStrictBase64("ck_s32_b64", serialized.ck_s32_b64)
      : undefined,
    ck_r32: serialized.ck_r32_b64
      ? decodeStrictBase64("ck_r32_b64", serialized.ck_r32_b64)
      : undefined,
    ns: serialized.ns,
    nr: serialized.nr,
    pn: serialized.pn,
    dh_self: {
      priv32: decodeStrictBase64("dh_self.priv32_b64", serialized.dh_self.priv32_b64),
      pub32: decodeStrictBase64("dh_self.pub32_b64", serialized.dh_self.pub32_b64),
    },
    dh_remote_pub32: decodeStrictBase64(
      "dh_remote_pub32_b64",
      serialized.dh_remote_pub32_b64
    ),
    skipped: new Map(
      serialized.skipped.map(([id, mk_b64]) => [
        id,
        decodeStrictBase64("skipped.mk32_b64", mk_b64),
      ])
    ),
  };
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

export function deserializePersistedSessionV1(
  serialized: SerializedPersistedSessionV1
): PersistedSession {
  if (serialized.v !== 1) {
    throw new TypeError(
      `Unsupported serialized session version: ${(serialized as { v: unknown }).v}`
    );
  }
  return {
    version: serialized.version,
    state: deserializeRatchetStateV1(serialized.state),
  };
}

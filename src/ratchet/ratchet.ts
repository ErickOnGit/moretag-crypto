/**
 * The Double Ratchet (protocol v2), as DR §3 specifies it, with the session's
 * associated data AD in every AEAD.
 *
 * - RatchetInitAlice (DR §3.3): a fresh DHs, DHr = SPK_B,
 *   RK, CKs = KDF_RK(SK, DH(DHs, SPK_B)). See {@link ratchetInitInitiatorV2}.
 * - RatchetInitBob: DHs = a copy of the SPK pair, no DHr, RK = SK, no chains. The
 *   first received message runs the DH step, which draws a fresh DHs before Bob
 *   sends. See {@link ratchetInitResponderV2}.
 * - Per-message AAD = AD || H (crypto/aad.ts). The header's device ids come from AD
 *   by role; a received header whose ids differ from AD is refused before any key
 *   derivation or AEAD ({@link DeviceMismatchError}).
 * - Skipped keys: a single gap over MAX_SKIP_DERIVE (1,000, DR §3.5 MAX_SKIP)
 *   errors; the cache keeps MAX_SKIPPED_KEYS (2,000) by evicting the oldest.
 *
 * Random draws (normative): ratchetEncrypt draws one 24-byte nonce; ratchetDecrypt
 * draws one 32-byte DHs private exactly when the header's ratchet key differs from
 * DHr or DHr is absent, after the old chain's skipped keys are stored and the
 * receiving chain stepped, and nothing otherwise.
 *
 * Erasure (best effort, crypto/wipe.ts): DH outputs, message keys, evicted skipped
 * keys, and the root and chain keys a decrypt replaces in its working copy are
 * wiped, and so is the whole working copy when a decrypt fails. Arrays of the
 * caller's state are replaced, never wiped: the library wipes only what it made.
 */

import { generateX25519Keypair, x25519SharedSecret } from "../crypto/x25519.js";
import { kdfRootAndChainKey, kdfChainKey } from "../crypto/kdf.js";
import { aeadDecryptXChaCha20Poly1305, aeadEncryptXChaCha20Poly1305, randomNonce24 } from "../crypto/aead.js";
import { buildDeliveryAadFromDecodedV2 } from "../crypto/aad.js";
import { parseAssociatedDataV2 } from "../crypto/ad.js";
import { bytesToBase64, decodeStrictBase64 } from "../encoding/base64.js";
import {
  decodeGroupSlotV2,
  decodeHeaderV2,
  type DecodedHeaderV2,
  type GroupSlotV2,
  type HeaderProtoV2,
} from "../wire/header.js";
import {
  MAX_SKIP_DERIVE,
  MAX_SKIPPED_KEYS,
  MAX_PLAINTEXT_BYTES,
  MAX_CIPHERTEXT_BYTES,
} from "../crypto/limits.js";
import { timingSafeEqual } from "../crypto/validation.js";
import { wipe } from "../crypto/wipe.js";
import { DeviceMismatchError, NoSendingChainError, ReplayDetectedError } from "../errors.js";
import { skippedKeyId } from "./skipped-id.js";

/** Which side of the X3DH setup this state belongs to, for the whole session. */
export type RatchetRole = "initiator" | "responder";

export interface RatchetState {
  version: 2;
  role: RatchetRole;
  /** The session's 164-byte associated data (crypto/ad.ts). */
  ad: Uint8Array;
  rk32: Uint8Array;
  ck_s32: Uint8Array | undefined;
  ck_r32: Uint8Array | undefined;
  ns: number;
  nr: number;
  pn: number;
  dh_self: { priv32: Uint8Array; pub32: Uint8Array };
  /** The peer's current ratchet key; absent on a responder before its first message. */
  dh_remote_pub32: Uint8Array | undefined;
  skipped: Map<string, Uint8Array>;
}

function assertKey32(label: string, key: Uint8Array): void {
  if (!(key instanceof Uint8Array) || key.byteLength !== 32) {
    throw new TypeError(`Invalid ${label} length: expected 32 bytes`);
  }
}

/** Wipes every secret array of a state this library made (a working copy). */
function wipeRatchetState(state: RatchetState): void {
  wipe(state.rk32, state.ck_s32, state.ck_r32, state.dh_self.priv32);
  for (const mk of state.skipped.values()) wipe(mk);
}

/** A deep copy: no array is shared with the input. */
export function cloneRatchetState(state: RatchetState): RatchetState {
  return {
    version: state.version,
    role: state.role,
    ad: new Uint8Array(state.ad),
    rk32: new Uint8Array(state.rk32),
    ck_s32: state.ck_s32 ? new Uint8Array(state.ck_s32) : undefined,
    ck_r32: state.ck_r32 ? new Uint8Array(state.ck_r32) : undefined,
    ns: state.ns,
    nr: state.nr,
    pn: state.pn,
    dh_self: {
      priv32: new Uint8Array(state.dh_self.priv32),
      pub32: new Uint8Array(state.dh_self.pub32),
    },
    dh_remote_pub32: state.dh_remote_pub32 ? new Uint8Array(state.dh_remote_pub32) : undefined,
    skipped: new Map(
      Array.from(state.skipped.entries()).map(([k, v]) => [k, new Uint8Array(v)])
    ),
  };
}

function assignState(target: RatchetState, src: RatchetState): void {
  target.version = src.version;
  target.role = src.role;
  target.ad = src.ad;
  target.rk32 = src.rk32;
  target.ck_s32 = src.ck_s32;
  target.ck_r32 = src.ck_r32;
  target.ns = src.ns;
  target.nr = src.nr;
  target.pn = src.pn;
  target.dh_self = src.dh_self;
  target.dh_remote_pub32 = src.dh_remote_pub32;
  target.skipped = src.skipped;
}

/** The state's own device id and its peer's, read from AD by role. */
function sessionDevices(state: RatchetState): { self: string; peer: string } {
  const ad = parseAssociatedDataV2(state.ad);
  return state.role === "initiator"
    ? { self: ad.initiator_device_id, peer: ad.responder_device_id }
    : { self: ad.responder_device_id, peer: ad.initiator_device_id };
}

function assertState(state: RatchetState): void {
  if (state.version !== 2) throw new TypeError("Unsupported ratchet state version");
  if (state.role !== "initiator" && state.role !== "responder") {
    throw new TypeError("Invalid ratchet state role");
  }
}

/**
 * Keeps at most MAX_SKIPPED_KEYS skipped message keys. At the cap the oldest one
 * (a Map iterates in insertion order) is dropped, so a long gap costs the oldest
 * missing messages rather than refusing every later one. A message whose key was
 * dropped is then refused: as a replay on the current receiving chain, by the
 * AEAD on an earlier one.
 */
function storeSkipped(state: RatchetState, dhPub32: Uint8Array, n: number, mk32: Uint8Array): void {
  if (state.skipped.size >= MAX_SKIPPED_KEYS) {
    const oldest = state.skipped.keys().next();
    if (!oldest.done) {
      wipe(state.skipped.get(oldest.value));
      state.skipped.delete(oldest.value);
    }
  }
  state.skipped.set(skippedKeyId(dhPub32, n), mk32);
}

/** DR §3.4 SkipMessageKeys: stores the receiving chain's keys up to `until`. */
function skipMessageKeys(state: RatchetState, until: number): void {
  if (until - state.nr > MAX_SKIP_DERIVE) {
    throw new Error("Max skip derivation window exceeded");
  }
  if (state.ck_r32 === undefined || state.dh_remote_pub32 === undefined) return;
  while (state.nr < until) {
    const { ck32, mk32 } = kdfChainKey(state.ck_r32);
    storeSkipped(state, state.dh_remote_pub32, state.nr, mk32);
    wipe(state.ck_r32);
    state.ck_r32 = ck32;
    state.nr += 1;
  }
}

/**
 * DR §3.4 DHRatchet on a working copy: one 32-byte draw for the new DHs. The
 * replaced root, chain and private keys belong to the copy and are wiped.
 */
function dhRatchetStep(state: RatchetState, remoteDhPub32: Uint8Array): void {
  state.pn = state.ns;
  state.ns = 0;
  state.nr = 0;
  state.dh_remote_pub32 = new Uint8Array(remoteDhPub32);

  const dhRecv = x25519SharedSecret(state.dh_self.priv32, remoteDhPub32);
  const recv = kdfRootAndChainKey(state.rk32, dhRecv);
  wipe(dhRecv, state.rk32, state.ck_r32);
  state.rk32 = recv.rk32;
  state.ck_r32 = recv.ck32;

  const oldSelf = state.dh_self;
  state.dh_self = generateX25519Keypair();
  wipe(oldSelf.priv32);

  const dhSend = x25519SharedSecret(state.dh_self.priv32, remoteDhPub32);
  const send = kdfRootAndChainKey(state.rk32, dhSend);
  wipe(dhSend, state.rk32, state.ck_s32);
  state.rk32 = send.rk32;
  state.ck_s32 = send.ck32;
}

/**
 * RatchetInitAlice (DR §3.3) for the X3DH initiator: draws a fresh DHs (one
 * 32-byte draw), sets DHr = the responder's signed prekey and derives
 * RK, CKs = KDF_RK(SK, DH(DHs, SPK_B)). Every input is copied.
 */
export function ratchetInitInitiatorV2(args: {
  sk32: Uint8Array;
  ad: Uint8Array;
  remoteSpkPub32: Uint8Array;
}): RatchetState {
  assertKey32("sk32", args.sk32);
  assertKey32("remoteSpkPub32", args.remoteSpkPub32);
  parseAssociatedDataV2(args.ad);
  const dh_self = generateX25519Keypair();
  const dh = x25519SharedSecret(dh_self.priv32, args.remoteSpkPub32);
  const { rk32, ck32 } = kdfRootAndChainKey(args.sk32, dh);
  wipe(dh);
  return {
    version: 2,
    role: "initiator",
    ad: new Uint8Array(args.ad),
    rk32,
    ck_s32: ck32,
    ck_r32: undefined,
    ns: 0,
    nr: 0,
    pn: 0,
    dh_self,
    dh_remote_pub32: new Uint8Array(args.remoteSpkPub32),
    skipped: new Map(),
  };
}

/**
 * RatchetInitBob (DR §3.3) for the X3DH responder: DHs = a copy of the signed
 * prekey pair, no DHr, RK = SK, no chains. No draw. Every input is copied, so the
 * state never aliases the prekey manager's keys.
 */
export function ratchetInitResponderV2(args: {
  sk32: Uint8Array;
  ad: Uint8Array;
  selfSpk: { priv32: Uint8Array; pub32: Uint8Array };
}): RatchetState {
  assertKey32("sk32", args.sk32);
  assertKey32("selfSpk.priv32", args.selfSpk.priv32);
  assertKey32("selfSpk.pub32", args.selfSpk.pub32);
  parseAssociatedDataV2(args.ad);
  return {
    version: 2,
    role: "responder",
    ad: new Uint8Array(args.ad),
    rk32: new Uint8Array(args.sk32),
    ck_s32: undefined,
    ck_r32: undefined,
    ns: 0,
    nr: 0,
    pn: 0,
    dh_self: {
      priv32: new Uint8Array(args.selfSpk.priv32),
      pub32: new Uint8Array(args.selfSpk.pub32),
    },
    dh_remote_pub32: undefined,
    skipped: new Map(),
  };
}

/**
 * Encrypts one message and advances `state` in place. The header's device ids
 * come from AD by role; `grp` (a group id and membership epoch) is authenticated
 * in H when given, and pairwise messages leave it out. Draws one 24-byte nonce.
 *
 * @throws NoSendingChainError when the state has no sending chain (a responder
 *   before its first received message)
 */
export function ratchetEncrypt(args: {
  state: RatchetState;
  plaintext: Uint8Array;
  grp?: GroupSlotV2;
}): { state: RatchetState; header: HeaderProtoV2; ciphertext_b64: string } {
  const { state, plaintext } = args;
  assertState(state);
  if (plaintext.byteLength > MAX_PLAINTEXT_BYTES) {
    throw new TypeError(`Plaintext too large: max ${MAX_PLAINTEXT_BYTES} bytes`);
  }
  const grp = decodeGroupSlotV2(args.grp);
  if (state.ck_s32 === undefined) throw new NoSendingChainError();
  const { self, peer } = sessionDevices(state);

  const { ck32, mk32 } = kdfChainKey(state.ck_s32);
  const decoded: DecodedHeaderV2 = {
    nonce24: randomNonce24(),
    sender_device_id: self,
    recipient_device_id: peer,
    dh_pub32: state.dh_self.pub32,
    pn: state.pn,
    n: state.ns,
    grp,
  };
  const aad = buildDeliveryAadFromDecodedV2(state.ad, decoded);
  let ciphertext: Uint8Array;
  try {
    ciphertext = aeadEncryptXChaCha20Poly1305(mk32, decoded.nonce24, plaintext, aad);
  } finally {
    wipe(mk32);
  }

  const header: HeaderProtoV2 = {
    v: 2,
    alg: "xchacha20poly1305",
    nonce_b64: bytesToBase64(decoded.nonce24),
    sender_device_id: self,
    recipient_device_id: peer,
    dr: { dh_pub_b64: bytesToBase64(state.dh_self.pub32), pn: state.pn, n: state.ns },
    ...(grp ? { grp } : {}),
  };
  state.ck_s32 = ck32;
  state.ns += 1;
  return { state, header, ciphertext_b64: bytesToBase64(ciphertext) };
}

/**
 * Decrypts one message and advances `state` in place, only on success: all work
 * runs on a copy, so a throw leaves `state` exactly as it was.
 *
 * Order: the header is checked (version, shape, canonical ids, group slot); its
 * ids must be the peer's and this device's as AD names them
 * ({@link DeviceMismatchError}); a stored skipped key for (dh_pub, n) is used if
 * present; otherwise a message on the current receiving chain with n below the
 * next expected number is {@link ReplayDetectedError}, raised before any key
 * derivation or AEAD; otherwise the DH step runs when dh_pub differs from DHr (or
 * DHr is absent), the chain is skipped to n, and the AEAD runs under AD || H.
 *
 * Limits: a replay from an earlier receiving chain is not recognised and fails
 * authentication instead ({@link DecryptFailedError}), and nothing here survives
 * the loss or rollback of the stored state: a state restored from before the
 * message was read accepts it again. It is not a persistent replay cache.
 *
 * @returns the plaintext and the authenticated group slot (null when pairwise)
 */
export function ratchetDecrypt(args: {
  state: RatchetState;
  header: HeaderProtoV2;
  ciphertext_b64: string;
}): { state: RatchetState; plaintext: Uint8Array; grp: GroupSlotV2 | null } {
  const { state } = args;
  assertState(state);
  const h = decodeHeaderV2(args.header);
  const { self, peer } = sessionDevices(state);
  if (h.sender_device_id !== peer || h.recipient_device_id !== self) {
    throw new DeviceMismatchError();
  }
  const ciphertext = decodeStrictBase64("ciphertext_b64", args.ciphertext_b64);
  if (ciphertext.byteLength > MAX_CIPHERTEXT_BYTES) {
    throw new TypeError(`Ciphertext too large: max ${MAX_CIPHERTEXT_BYTES} bytes`);
  }
  const aad = buildDeliveryAadFromDecodedV2(state.ad, h);
  const working = cloneRatchetState(state);
  let committed = false;
  let mk32: Uint8Array | undefined;
  try {
    const skippedId = skippedKeyId(h.dh_pub32, h.n);
    mk32 = working.skipped.get(skippedId);
    if (mk32) {
      const plaintext = aeadDecryptXChaCha20Poly1305(mk32, h.nonce24, ciphertext, aad);
      working.skipped.delete(skippedId);
      assignState(state, working);
      committed = true;
      return { state, plaintext, grp: h.grp };
    }

    const sameChain =
      working.dh_remote_pub32 !== undefined && timingSafeEqual(h.dh_pub32, working.dh_remote_pub32);
    if (sameChain && working.ck_r32 !== undefined && h.n < working.nr) {
      // Its key was either used in order or taken from the skipped cache above.
      throw new ReplayDetectedError();
    }
    if (!sameChain) {
      skipMessageKeys(working, h.pn);
      dhRatchetStep(working, h.dh_pub32);
    }
    skipMessageKeys(working, h.n);
    if (working.ck_r32 === undefined) throw new Error("Receive chain not initialized");
    const step = kdfChainKey(working.ck_r32);
    mk32 = step.mk32;
    wipe(working.ck_r32);
    working.ck_r32 = step.ck32;
    working.nr += 1;

    const plaintext = aeadDecryptXChaCha20Poly1305(mk32, h.nonce24, ciphertext, aad);
    assignState(state, working);
    committed = true;
    return { state, plaintext, grp: h.grp };
  } finally {
    wipe(mk32);
    if (!committed) wipeRatchetState(working);
  }
}

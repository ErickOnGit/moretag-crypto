import { generateX25519Keypair, x25519SharedSecret } from "../crypto/x25519.js";
import { kdfRootAndChainKey, kdfChainKey } from "../crypto/kdf.js";
import { randomNonce24 } from "../crypto/aead.js";
import { sealDeliveryV1, openDeliveryV1 } from "../crypto/seal.js";
import { bytesToBase64, decodeStrictBase64 } from "../encoding/base64.js";
import type { HeaderProtoV1 } from "../wire/header.js";
import {
  MAX_SKIP_DERIVE,
  MAX_SKIPPED_KEYS,
  MAX_PLAINTEXT_BYTES,
  MAX_CIPHERTEXT_BYTES,
  MAX_DEVICE_ID_BYTES,
} from "../crypto/limits.js";
import { assertBoundedString, timingSafeEqual } from "../crypto/validation.js";

export interface RatchetState {
  version: 1;
  rk32: Uint8Array;
  ck_s32: Uint8Array | undefined;
  ck_r32: Uint8Array | undefined;
  ns: number;
  nr: number;
  pn: number;
  dh_self: { priv32: Uint8Array; pub32: Uint8Array };
  dh_remote_pub32: Uint8Array;
  skipped: Map<string, Uint8Array>;
}

function skippedKeyId(dhPub32: Uint8Array, n: number): string {
  return `${bytesToBase64(dhPub32)}:${n}`;
}

function assertKey32(label: string, key: Uint8Array): void {
  if (key.byteLength !== 32) {
    throw new TypeError(`Invalid ${label} length: expected 32 bytes, got ${key.byteLength}`);
  }
}

function cloneState(state: RatchetState): RatchetState {
  return {
    version: state.version,
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
    dh_remote_pub32: new Uint8Array(state.dh_remote_pub32),
    skipped: new Map(
      Array.from(state.skipped.entries()).map(([k, v]) => [k, new Uint8Array(v)])
    ),
  };
}

function assignState(target: RatchetState, src: RatchetState): void {
  target.version = src.version;
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

function storeSkipped(
  state: RatchetState,
  dhPub32: Uint8Array,
  n: number,
  mk32: Uint8Array
): void {
  if (state.skipped.size >= MAX_SKIPPED_KEYS) {
    throw new Error("Skipped message key limit exceeded");
  }
  state.skipped.set(skippedKeyId(dhPub32, n), mk32);
}

function useSkipped(state: RatchetState, header: HeaderProtoV1): Uint8Array | undefined {
  const dhPub = decodeStrictBase64("dr.dh_pub_b64", header.dr.dh_pub_b64);
  const key = skippedKeyId(dhPub, header.dr.n);
  const mk = state.skipped.get(key);
  if (mk) {
    state.skipped.delete(key);
  }
  return mk;
}

function deriveUntil(
  state: RatchetState,
  target: number,
  dhPub32: Uint8Array
): void {
  if (state.ck_r32 === undefined) {
    throw new Error("Receive chain is not initialized");
  }
  if (target - state.nr > MAX_SKIP_DERIVE) {
    throw new Error("Max skip derivation window exceeded");
  }
  while (state.nr < target) {
    const { ck32, mk32 } = kdfChainKey(state.ck_r32);
    state.ck_r32 = ck32;
    storeSkipped(state, dhPub32, state.nr, mk32);
    state.nr += 1;
  }
}

function applyReceiverRatchet(
  state: RatchetState,
  remoteDhPub32: Uint8Array,
  pn: number
): void {
  // catch up skipped messages on previous chain
  if (pn > state.nr) {
    deriveUntil(state, pn, state.dh_remote_pub32);
  }

  const dhRecv = x25519SharedSecret(state.dh_self.priv32, remoteDhPub32);
  const recvStep = kdfRootAndChainKey(state.rk32, dhRecv);

  const newSelf = generateX25519Keypair();
  const dhSend = x25519SharedSecret(newSelf.priv32, remoteDhPub32);
  const sendStep = kdfRootAndChainKey(recvStep.rk32, dhSend);

  state.rk32 = sendStep.rk32;
  state.ck_r32 = recvStep.ck32;
  state.ck_s32 = sendStep.ck32;
  state.dh_remote_pub32 = remoteDhPub32;
  state.dh_self = newSelf;
  state.pn = state.ns;
  state.ns = 0;
  state.nr = 0;
}

function sendRatchet(state: RatchetState): void {
  const newSelf = generateX25519Keypair();
  const dh = x25519SharedSecret(newSelf.priv32, state.dh_remote_pub32);
  const { rk32, ck32 } = kdfRootAndChainKey(state.rk32, dh);
  state.rk32 = rk32;
  state.ck_s32 = ck32;
  state.dh_self = newSelf;
  state.pn = state.ns;
  state.ns = 0;
}

export function ratchetInit(params: {
  rk32: Uint8Array;
  selfDh?: { priv32: Uint8Array; pub32: Uint8Array };
  remoteDhPub32: Uint8Array;
  sendingFirst: boolean;
}): RatchetState {
  assertKey32("rk32", params.rk32);
  assertKey32("remoteDhPub32", params.remoteDhPub32);
  const selfDh = params.selfDh ?? generateX25519Keypair();
  assertKey32("selfDh.priv32", selfDh.priv32);
  assertKey32("selfDh.pub32", selfDh.pub32);
  const dh = x25519SharedSecret(selfDh.priv32, params.remoteDhPub32);
  const { rk32, ck32 } = kdfRootAndChainKey(params.rk32, dh);

  return {
    version: 1,
    rk32,
    ck_s32: params.sendingFirst ? ck32 : undefined,
    ck_r32: params.sendingFirst ? undefined : ck32,
    ns: 0,
    nr: 0,
    pn: 0,
    dh_self: selfDh,
    dh_remote_pub32: params.remoteDhPub32,
    skipped: new Map(),
  };
}

export function ratchetEncrypt(args: {
  state: RatchetState;
  plaintext: Uint8Array;
  sender_device_id: string;
  recipient_device_id: string;
  advanceDh?: boolean;
}): { state: RatchetState; header: HeaderProtoV1; ciphertext_b64: string } {
  const { state, plaintext, sender_device_id, recipient_device_id, advanceDh } = args;

  if (plaintext.byteLength > MAX_PLAINTEXT_BYTES) {
    throw new TypeError(`Plaintext too large: max ${MAX_PLAINTEXT_BYTES} bytes`);
  }
  assertBoundedString("sender_device_id", sender_device_id, MAX_DEVICE_ID_BYTES);
  assertBoundedString("recipient_device_id", recipient_device_id, MAX_DEVICE_ID_BYTES);

  if (advanceDh || state.ck_s32 === undefined) {
    sendRatchet(state);
  }

  if (state.ck_s32 === undefined) {
    throw new Error("Send chain not initialized");
  }

  const { ck32, mk32 } = kdfChainKey(state.ck_s32);
  state.ck_s32 = ck32;

  const nonce = randomNonce24();
  const header: HeaderProtoV1 = {
    v: 1,
    alg: "xchacha20poly1305",
    nonce_b64: bytesToBase64(nonce),
    sender_device_id,
    recipient_device_id,
    dr: {
      dh_pub_b64: bytesToBase64(state.dh_self.pub32),
      pn: state.pn,
      n: state.ns,
    },
  };

  state.ns += 1;

  const { ciphertext_b64 } = sealDeliveryV1({
    key32: mk32,
    header,
    plaintext,
  });

  return { state, header, ciphertext_b64 };
}

export function ratchetDecrypt(args: {
  state: RatchetState;
  header: HeaderProtoV1;
  ciphertext_b64: string;
}): { state: RatchetState; plaintext: Uint8Array } {
  const { state, header, ciphertext_b64 } = args;
  const working = cloneState(state);

  if (header.v !== 1 || header.alg !== "xchacha20poly1305") {
    throw new TypeError("Unsupported header version or algorithm");
  }
  assertBoundedString("header.sender_device_id", header.sender_device_id, MAX_DEVICE_ID_BYTES);
  assertBoundedString("header.recipient_device_id", header.recipient_device_id, MAX_DEVICE_ID_BYTES);

  const skipped = useSkipped(working, header);
  if (skipped) {
    const plaintext = openDeliveryV1({
      key32: skipped,
      header,
      ciphertext_b64,
    });
    assignState(state, working);
    return { state, plaintext };
  }

  const remoteDhPub32 = decodeStrictBase64("dr.dh_pub_b64", header.dr.dh_pub_b64);
  assertKey32("dr.dh_pub_b64 decoded", remoteDhPub32);

  if (!timingSafeEqual(remoteDhPub32, working.dh_remote_pub32)) {
    applyReceiverRatchet(working, remoteDhPub32, header.dr.pn);
  }

  deriveUntil(working, header.dr.n, working.dh_remote_pub32);

  if (working.ck_r32 === undefined) {
    throw new Error("Receive chain not initialized");
  }

  const { ck32, mk32 } = kdfChainKey(working.ck_r32);
  working.ck_r32 = ck32;
  working.nr += 1;

  const plaintext = openDeliveryV1({
    key32: mk32,
    header,
    ciphertext_b64,
  });

  assignState(state, working);
  return { state, plaintext };
}

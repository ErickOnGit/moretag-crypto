/**
 * X3DH (protocol v2): X25519, SHA-256, a separate Ed25519 signing key.
 *
 *   DH1 = DH(IK_A, SPK_B)   DH2 = DH(EK_A, IK_B)   DH3 = DH(EK_A, SPK_B)
 *   DH4 = DH(EK_A, OPK_B)   only when the bundle carried a one-time prekey
 *   KM  = F || DH1 || DH2 || DH3 [|| DH4]          F = 32 bytes of 0xFF (X3DH §2.2)
 *   SK  = HKDF-SHA256(salt = 32 zero bytes, ikm = KM, info = "moretag/x3dh/v2", 32)
 *
 * F matches X3DH §2.2's KDF input. Its stated purpose is domain separation from
 * XEdDSA's hashes when one key both signs and does DH; our X25519 key never signs,
 * so F has no security purpose here. Every DH output is refused when all zero.
 *
 * The initiator verifies the signed-prekey signature, then that the bundle names
 * the device it asked for, before any DH. Both sides return SK and the 164-byte AD
 * (crypto/ad.ts); A is always the initiator.
 */

import { bytesToBase64 } from "../encoding/base64.js";
import { encodeCbor } from "../encoding/cbor.js";
import { generateX25519Keypair, x25519PublicFromPrivate, x25519SharedSecret } from "./x25519.js";
import { hkdfSha256 } from "./hkdf.js";
import { ed25519Verify } from "./ed25519.js";
import { buildAssociatedDataV2 } from "./ad.js";
import { assertCanonicalDeviceId } from "./device-id.js";
import { wipe } from "./wipe.js";
import {
  BadSignatureError,
  DeviceMismatchError,
  SelfSessionError,
} from "../errors.js";
import {
  X3DH_ALG_V2,
  decodePrekeyBundleV2,
  decodeSessionInitV2,
  isPrekeyId,
  type DecodedPrekeyBundleV2,
  type DecodedSessionInitV2,
  type X3DHPrekeyBundleV2,
  type X3DHSessionInitV2,
} from "../wire/x3dh.js";

const ENC = new TextEncoder();
const X3DH_INFO = ENC.encode("moretag/x3dh/v2");
const X3DH_SALT = new Uint8Array(32);
const F_LENGTH = 32;

/** Domain string of the signed-prekey signature (unchanged since v1). */
export const SPK_SIGNATURE_DOMAIN = "moretag/x3dh/spk/v1";
/** Domain string of the one-time prekey batch signature. */
export const OPK_BATCH_SIGNATURE_DOMAIN = "moretag/x3dh/opk-batch/v1";

function key32(label: string, key: Uint8Array): void {
  if (!(key instanceof Uint8Array) || key.byteLength !== 32) {
    throw new TypeError(`Invalid ${label} length: expected 32 bytes`);
  }
}

/**
 * The message an identity signing key signs for a signed prekey:
 *   CBOR ["moretag/x3dh/spk/v1", device_id, IK (bstr 32), SPK (bstr 32), spk_id]
 * The device id is a text string, as written. Unchanged from v1: its bytes are
 * shared with the server's copy and the app's golden vector.
 */
export function buildSpkSigMessage(args: {
  recipient_device_id: string;
  ik_pub32: Uint8Array;
  spk_pub32: Uint8Array;
  spk_id: number;
}): Uint8Array {
  key32("ik_pub32", args.ik_pub32);
  key32("spk_pub32", args.spk_pub32);
  return encodeCbor([
    SPK_SIGNATURE_DOMAIN,
    args.recipient_device_id,
    args.ik_pub32,
    args.spk_pub32,
    args.spk_id,
  ]);
}

/**
 * The message an identity signing key signs for a batch of one-time prekeys:
 *   CBOR ["moretag/x3dh/opk-batch/v1", device_id, [[id, key (bstr 32)], ...]]
 * in the order given. The device id is a canonical UUID text string, the ids
 * 1..2^31-1 and unique.
 */
export function buildOpkBatchSigMessage(args: {
  device_id: string;
  prekeys: ReadonlyArray<{ opk_id: number; pub32: Uint8Array }>;
}): Uint8Array {
  assertCanonicalDeviceId(args.device_id);
  const seen = new Set<number>();
  const entries = args.prekeys.map((p) => {
    if (!isPrekeyId(p.opk_id) || seen.has(p.opk_id)) {
      throw new TypeError("One-time prekey ids must be unique integers 1..2^31-1");
    }
    seen.add(p.opk_id);
    key32("one-time prekey", p.pub32);
    return [p.opk_id, p.pub32] as const;
  });
  return encodeCbor([OPK_BATCH_SIGNATURE_DOMAIN, args.device_id, entries]);
}

/** SK from the DH outputs in order: HKDF over F || DH1 || ... (X3DH §2.2). KM is wiped. */
function deriveSk(dhOutputs: readonly Uint8Array[]): Uint8Array {
  const km = new Uint8Array(F_LENGTH + 32 * dhOutputs.length);
  km.fill(0xff, 0, F_LENGTH);
  dhOutputs.forEach((dh, i) => km.set(dh, F_LENGTH + 32 * i));
  try {
    return hkdfSha256(km, X3DH_SALT, X3DH_INFO, 32);
  } finally {
    wipe(km);
  }
}

/**
 * Verifies a bundle in the initiator's order: shape, then the signed-prekey
 * signature ({@link BadSignatureError}), then that it names the expected device
 * ({@link DeviceMismatchError}). Returns the decoded fields.
 */
export function verifyPrekeyBundleV2(
  bundle: X3DHPrekeyBundleV2,
  expected_recipient_device_id: string
): DecodedPrekeyBundleV2 {
  const b = decodePrekeyBundleV2(bundle);
  assertCanonicalDeviceId(expected_recipient_device_id);
  const message = buildSpkSigMessage({
    recipient_device_id: b.recipient_device_id,
    ik_pub32: b.ik_pub32,
    spk_pub32: b.spk_pub32,
    spk_id: b.spk_id,
  });
  if (!ed25519Verify(b.ik_sig_pub32, message, b.spk_sig64)) throw new BadSignatureError();
  if (b.recipient_device_id !== expected_recipient_device_id) throw new DeviceMismatchError();
  return b;
}

/** The initiator's computation on a verified bundle. Draws the EK (one 32-byte draw). */
export function x3dhInitiatorFromVerifiedBundle(args: {
  sender_device_id: string;
  bundle: DecodedPrekeyBundleV2;
  initiator_ik_priv32: Uint8Array;
  initiator_ik_sig_pub32: Uint8Array;
}): { sk32: Uint8Array; ad: Uint8Array; session_init: X3DHSessionInitV2 } {
  const { bundle: b } = args;
  key32("initiator_ik_priv32", args.initiator_ik_priv32);
  key32("initiator_ik_sig_pub32", args.initiator_ik_sig_pub32);
  assertCanonicalDeviceId(args.sender_device_id);
  if (args.sender_device_id === b.recipient_device_id) throw new SelfSessionError();

  const ik_a_pub32 = x25519PublicFromPrivate(args.initiator_ik_priv32);
  const ad = buildAssociatedDataV2({
    initiator_ik_pub32: ik_a_pub32,
    responder_ik_pub32: b.ik_pub32,
    initiator_ik_sig_pub32: args.initiator_ik_sig_pub32,
    responder_ik_sig_pub32: b.ik_sig_pub32,
    initiator_device_id: args.sender_device_id,
    responder_device_id: b.recipient_device_id,
  });

  const ek = generateX25519Keypair();
  const dhs: Uint8Array[] = [];
  let sk32: Uint8Array;
  try {
    dhs.push(x25519SharedSecret(args.initiator_ik_priv32, b.spk_pub32));
    dhs.push(x25519SharedSecret(ek.priv32, b.ik_pub32));
    dhs.push(x25519SharedSecret(ek.priv32, b.spk_pub32));
    if (b.opk) dhs.push(x25519SharedSecret(ek.priv32, b.opk.pub32));
    sk32 = deriveSk(dhs);
  } finally {
    wipe(ek.priv32, ...dhs);
  }

  const session_init: X3DHSessionInitV2 = {
    v: 2,
    alg: X3DH_ALG_V2,
    sender_device_id: args.sender_device_id,
    recipient_device_id: b.recipient_device_id,
    sender_ik_pub_b64: bytesToBase64(ik_a_pub32),
    sender_ik_sig_pub_b64: bytesToBase64(args.initiator_ik_sig_pub32),
    ek_pub_b64: bytesToBase64(ek.pub32),
    spk_id: b.spk_id,
    used_opk: b.opk !== undefined,
    ...(b.opk ? { opk_id: b.opk.opk_id } : {}),
  };
  return { sk32, ad, session_init };
}

/**
 * X3DH initiator: verifies the bundle (signature, then expected device), draws the
 * EK, and returns SK, AD and the session_init sidecar. The EK private key never
 * leaves this function.
 */
export function x3dhInitiatorV2(args: {
  sender_device_id: string;
  recipient_bundle: X3DHPrekeyBundleV2;
  expected_recipient_device_id: string;
  initiator_ik_priv32: Uint8Array;
  initiator_ik_sig_pub32: Uint8Array;
}): { sk32: Uint8Array; ad: Uint8Array; session_init: X3DHSessionInitV2 } {
  const bundle = verifyPrekeyBundleV2(args.recipient_bundle, args.expected_recipient_device_id);
  return x3dhInitiatorFromVerifiedBundle({
    sender_device_id: args.sender_device_id,
    bundle,
    initiator_ik_priv32: args.initiator_ik_priv32,
    initiator_ik_sig_pub32: args.initiator_ik_sig_pub32,
  });
}

/**
 * The responder's checks on a sidecar against the host's view: the sender must be
 * the server row's sender device and the recipient this device
 * ({@link DeviceMismatchError}), and the two must differ ({@link SelfSessionError}).
 */
export function checkSessionInitDevicesV2(
  si: DecodedSessionInitV2,
  sender_device_id: string,
  recipient_device_id: string
): void {
  assertCanonicalDeviceId(sender_device_id);
  assertCanonicalDeviceId(recipient_device_id);
  if (sender_device_id === recipient_device_id || si.sender_device_id === si.recipient_device_id) {
    throw new SelfSessionError();
  }
  if (si.sender_device_id !== sender_device_id) throw new DeviceMismatchError();
  if (si.recipient_device_id !== recipient_device_id) throw new DeviceMismatchError();
}

/** The responder's computation on a checked sidecar. No draw. */
export function x3dhResponderFromDecoded(args: {
  session_init: DecodedSessionInitV2;
  recipient_ik_priv32: Uint8Array;
  recipient_ik_sig_pub32: Uint8Array;
  recipient_spk_priv32: Uint8Array;
  recipient_opk_priv32?: Uint8Array | undefined;
}): { sk32: Uint8Array; ad: Uint8Array } {
  const si = args.session_init;
  key32("recipient_ik_priv32", args.recipient_ik_priv32);
  key32("recipient_ik_sig_pub32", args.recipient_ik_sig_pub32);
  key32("recipient_spk_priv32", args.recipient_spk_priv32);
  if ((si.opk_id !== undefined) !== (args.recipient_opk_priv32 !== undefined)) {
    throw new TypeError("recipient_opk_priv32 is required exactly when the setup used a one-time prekey");
  }
  if (args.recipient_opk_priv32) key32("recipient_opk_priv32", args.recipient_opk_priv32);

  const dhs: Uint8Array[] = [];
  let sk32: Uint8Array;
  try {
    dhs.push(x25519SharedSecret(args.recipient_spk_priv32, si.sender_ik_pub32));
    dhs.push(x25519SharedSecret(args.recipient_ik_priv32, si.ek_pub32));
    dhs.push(x25519SharedSecret(args.recipient_spk_priv32, si.ek_pub32));
    if (args.recipient_opk_priv32) dhs.push(x25519SharedSecret(args.recipient_opk_priv32, si.ek_pub32));
    sk32 = deriveSk(dhs);
  } finally {
    wipe(...dhs);
  }

  const ad = buildAssociatedDataV2({
    initiator_ik_pub32: si.sender_ik_pub32,
    responder_ik_pub32: x25519PublicFromPrivate(args.recipient_ik_priv32),
    initiator_ik_sig_pub32: si.sender_ik_sig_pub32,
    responder_ik_sig_pub32: args.recipient_ik_sig_pub32,
    initiator_device_id: si.sender_device_id,
    responder_device_id: si.recipient_device_id,
  });
  return { sk32, ad };
}

/**
 * X3DH responder. `sender_device_id` is the sending device as the host knows it
 * (the server row), never the sidecar's own claim; a sidecar naming another
 * sender, or another recipient than `recipient_device_id`, is
 * {@link DeviceMismatchError}. Returns SK and AD.
 */
export function x3dhResponderV2(args: {
  session_init: X3DHSessionInitV2;
  sender_device_id: string;
  recipient_device_id: string;
  recipient_ik_priv32: Uint8Array;
  recipient_ik_sig_pub32: Uint8Array;
  recipient_spk_priv32: Uint8Array;
  recipient_opk_priv32?: Uint8Array;
}): { sk32: Uint8Array; ad: Uint8Array } {
  const si = decodeSessionInitV2(args.session_init);
  checkSessionInitDevicesV2(si, args.sender_device_id, args.recipient_device_id);
  return x3dhResponderFromDecoded({
    session_init: si,
    recipient_ik_priv32: args.recipient_ik_priv32,
    recipient_ik_sig_pub32: args.recipient_ik_sig_pub32,
    recipient_spk_priv32: args.recipient_spk_priv32,
    recipient_opk_priv32: args.recipient_opk_priv32,
  });
}

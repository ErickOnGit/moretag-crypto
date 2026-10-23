/**
 * Session bootstraps (protocol v2): X3DH followed by the Double Ratchet's
 * initialization, with identity pinning in the order the design requires.
 */

import type { X3DHPrekeyBundleV2, X3DHSessionInitV2 } from "../wire/x3dh.js";
import { decodeSessionInitV2 } from "../wire/x3dh.js";
import {
  checkSessionInitDevicesV2,
  verifyPrekeyBundleV2,
  x3dhInitiatorFromVerifiedBundle,
  x3dhResponderFromDecoded,
} from "../crypto/x3dh.js";
import { assertCanonicalDeviceId } from "../crypto/device-id.js";
import { bytesToBase64 } from "../encoding/base64.js";
import type { IdentityRegistry } from "../identity/trust.js";
import type { X3DHPrekeyManagerV2 } from "./prekey-manager.js";
import { DeviceMismatchError, SelfSessionError } from "../errors.js";
import {
  ratchetInitInitiatorV2,
  ratchetInitResponderV2,
  type RatchetState,
} from "../ratchet/ratchet.js";

/**
 * The initiator's bootstrap, in X3DH §3.3's order: verify the signed-prekey
 * signature ({@link BadSignatureError}), check that the bundle names
 * `expected_recipient_device_id` ({@link DeviceMismatchError}), then check and pin
 * the recipient's two identity keys on `trust` ({@link IdentityMismatchError} on a
 * changed identity), then run X3DH and RatchetInitAlice.
 *
 * Draws: the EK private (32 bytes), then the first DHs private (32 bytes). The EK
 * private key never leaves the library.
 *
 * Returns the ratchet state, ready to send, and the session_init sidecar the host
 * sends beside every message until a peer message decrypts on this session.
 */
export function x3dhInitiatorBootstrapV2(args: {
  sender_device_id: string;
  recipient_bundle: X3DHPrekeyBundleV2;
  expected_recipient_device_id: string;
  initiator_ik_priv32: Uint8Array;
  initiator_ik_sig_pub32: Uint8Array;
  trust: IdentityRegistry;
}): { session_init: X3DHSessionInitV2; ratchet_state: RatchetState } {
  assertCanonicalDeviceId(args.sender_device_id);
  assertCanonicalDeviceId(args.expected_recipient_device_id);
  if (args.sender_device_id === args.expected_recipient_device_id) throw new SelfSessionError();

  const bundle = verifyPrekeyBundleV2(args.recipient_bundle, args.expected_recipient_device_id);
  args.trust.assertOrPin({
    device_id: bundle.recipient_device_id,
    ik_pub_b64: bytesToBase64(bundle.ik_pub32),
    ik_sig_pub_b64: bytesToBase64(bundle.ik_sig_pub32),
  });

  const { sk32, ad, session_init } = x3dhInitiatorFromVerifiedBundle({
    sender_device_id: args.sender_device_id,
    bundle,
    initiator_ik_priv32: args.initiator_ik_priv32,
    initiator_ik_sig_pub32: args.initiator_ik_sig_pub32,
  });
  const ratchet_state = ratchetInitInitiatorV2({ sk32, ad, remoteSpkPub32: bundle.spk_pub32 });
  return { session_init, ratchet_state };
}

/**
 * The responder's bootstrap, in memory only. It reads the signed and one-time
 * prekeys without consuming them, takes no trust registry (the host checks and
 * pins only after the first message decrypts) and draws nothing.
 *
 * `sender_device_id` is the sending device from the server row, never the
 * sidecar's claim; `recipient_device_id` is this device. A sidecar naming another
 * sender or recipient is {@link DeviceMismatchError}; equal devices are
 * {@link SelfSessionError}; a prekey this device does not hold is
 * {@link UnknownPrekeyError} (`unknown_spk`, `unknown_opk`).
 *
 * Returns the responder state (RatchetInitBob) and the prekey ids the setup used,
 * so the host can delete the one-time prekey once the first message decrypts.
 */
export function x3dhResponderBootstrapV2(args: {
  session_init: X3DHSessionInitV2;
  prekeys: X3DHPrekeyManagerV2;
  recipient_device_id: string;
  sender_device_id: string;
}): { ratchet_state: RatchetState; used: { spk_id: number; opk_id?: number } } {
  const si = decodeSessionInitV2(args.session_init);
  checkSessionInitDevicesV2(si, args.sender_device_id, args.recipient_device_id);
  if (args.prekeys.recipient_device_id !== args.recipient_device_id) throw new DeviceMismatchError();

  const spk = args.prekeys.getSignedPrekey(si.spk_id);
  const opkPriv32 = si.opk_id !== undefined ? args.prekeys.getOneTimePrekeyPriv32(si.opk_id) : undefined;

  const { sk32, ad } = x3dhResponderFromDecoded({
    session_init: si,
    recipient_ik_priv32: args.prekeys.ik.priv32,
    recipient_ik_sig_pub32: args.prekeys.ik_sig.pub32,
    recipient_spk_priv32: spk.priv32,
    recipient_opk_priv32: opkPriv32,
  });
  const ratchet_state = ratchetInitResponderV2({ sk32, ad, selfSpk: spk });
  return {
    ratchet_state,
    used: { spk_id: si.spk_id, ...(si.opk_id !== undefined ? { opk_id: si.opk_id } : {}) },
  };
}

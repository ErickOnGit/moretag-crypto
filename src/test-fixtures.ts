/**
 * Shared test fixtures (not part of the build): canonical UUID device ids, and
 * session pairs made through the public bootstraps.
 */

import { IdentityRegistry } from "./identity/trust.js";
import { X3DHPrekeyManagerV2 } from "./x3dh/prekey-manager.js";
import { x3dhInitiatorBootstrapV2, x3dhResponderBootstrapV2 } from "./x3dh/session.js";
import { ratchetDecrypt, ratchetEncrypt, type RatchetState } from "./ratchet/ratchet.js";
import type { X3DHSessionInitV2 } from "./wire/x3dh.js";
import { bytesToBase64 } from "./encoding/base64.js";

export const ALICE_DEVICE = "0f0e5a3c-6b1d-4c2e-8a7f-1d2c3b4a5f60";
export const BOB_DEVICE = "4b8d2e6f-0a1c-4e3d-9b5a-7c6d5e4f3a21";
export const CAROL_DEVICE = "9a7c5e3b-1d2f-4a6b-8c0e-2f4a6c8e0b13";

export const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);

export interface SessionPair {
  alice: RatchetState;
  bob: RatchetState;
  aliceKeys: X3DHPrekeyManagerV2;
  bobKeys: X3DHPrekeyManagerV2;
  session_init: X3DHSessionInitV2;
}

/**
 * Alice (initiator) and Bob (responder) through the public bootstraps. Bob's state
 * has no sending chain until he decrypts a message; see {@link establishedPair}.
 * With `opkId`, Bob mints one-time prekeys and the bundle carries that one.
 */
export function sessionPair(opts: { opkId?: number } = {}): SessionPair {
  const aliceKeys = X3DHPrekeyManagerV2.create({ recipient_device_id: ALICE_DEVICE });
  const bobKeys = X3DHPrekeyManagerV2.create({ recipient_device_id: BOB_DEVICE });
  const bundle = bobKeys.getPrekeyBundle();
  if (opts.opkId !== undefined) {
    const [opk] = bobKeys.mintOneTimePrekeys(1, opts.opkId);
    bundle.opk_id = opk!.opk_id;
    bundle.opk_pub_b64 = bytesToBase64(opk!.pub32);
  }
  const init = x3dhInitiatorBootstrapV2({
    sender_device_id: ALICE_DEVICE,
    recipient_bundle: bundle,
    expected_recipient_device_id: BOB_DEVICE,
    initiator_ik_priv32: aliceKeys.ik.priv32,
    initiator_ik_sig_pub32: aliceKeys.ik_sig.pub32,
    trust: new IdentityRegistry(),
  });
  const resp = x3dhResponderBootstrapV2({
    session_init: init.session_init,
    prekeys: bobKeys,
    recipient_device_id: BOB_DEVICE,
    sender_device_id: ALICE_DEVICE,
  });
  return {
    alice: init.ratchet_state,
    bob: resp.ratchet_state,
    aliceKeys,
    bobKeys,
    session_init: init.session_init,
  };
}

/** A pair in which Bob has read one message from Alice, so both sides can send. */
export function establishedPair(): SessionPair {
  const pair = sessionPair();
  const first = ratchetEncrypt({ state: pair.alice, plaintext: utf8("hello") });
  ratchetDecrypt({ state: pair.bob, header: first.header, ciphertext_b64: first.ciphertext_b64 });
  return pair;
}

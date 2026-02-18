import type { X3DHPrekeyBundleV1, X3DHSessionInitV1 } from "../wire/x3dh.js";
import {
  decodeX25519PubB64,
  x3dhInitiatorV1,
  x3dhResponderV1,
} from "../crypto/x3dh.js";
import { generateX25519Keypair, x25519PublicFromPrivate } from "../crypto/x25519.js";
import type { IdentityRegistry } from "../identity/trust.js";
import type { X3DHPrekeyManagerV1 } from "./prekey-manager.js";
import { ratchetInit, type RatchetState } from "../ratchet/ratchet.js";
import { timingSafeEqual } from "../crypto/validation.js";

/**
 * Initiator helper that pins the recipient's X25519 identity key on first use.
 * If the identity changes later, it will throw unless the registry is configured to rotate.
 */
export function x3dhInitiatorWithTrustV1(args: {
  sender_device_id: string;
  recipient_bundle: X3DHPrekeyBundleV1;
  initiator_ik_priv32: Uint8Array;
  initiator_ek_priv32?: Uint8Array;
  trust: IdentityRegistry;
  allowRotateIdentity?: boolean;
}): { session_init: X3DHSessionInitV1; rk32: Uint8Array } {
  const { trust, recipient_bundle, allowRotateIdentity, ...rest } = args;
  trust.trust(
    recipient_bundle.recipient_device_id,
    recipient_bundle.ik_pub_b64,
    allowRotateIdentity ? { allowRotate: true } : undefined
  );
  return x3dhInitiatorV1({ ...rest, recipient_bundle });
}

/**
 * Responder helper that looks up SPK/OPK from the prekey manager and consumes OPKs.
 */
export function x3dhResponderWithPrekeysV1(args: {
  session_init: X3DHSessionInitV1;
  prekeys: X3DHPrekeyManagerV1;
  consumeOpk?: boolean;
  trust?: IdentityRegistry;
  allowRotateIdentity?: boolean;
}): { rk32: Uint8Array } {
  const { session_init, prekeys, trust, allowRotateIdentity } = args;
  if (session_init.recipient_device_id !== prekeys.recipient_device_id) {
    throw new Error(
      `recipient_device_id mismatch: expected ${prekeys.recipient_device_id}, got ${session_init.recipient_device_id}`
    );
  }
  if (trust) {
    trust.trust(
      session_init.sender_device_id,
      session_init.sender_ik_pub_b64,
      allowRotateIdentity ? { allowRotate: true } : undefined
    );
  }

  const recipient_ik_priv32 = prekeys.ik.priv32;
  const recipient_spk_priv32 = prekeys.getSignedPrekeyPriv32(session_init.spk_id);
  const recipient_opk_priv32 =
    session_init.used_opk && session_init.opk_id !== undefined
      ? (args.consumeOpk === false
          ? prekeys.getOneTimePrekeyPriv32(session_init.opk_id)
          : prekeys.consumeOneTimePrekey(session_init.opk_id).priv32)
      : undefined;

  const base = {
    session_init,
    recipient_ik_priv32,
    recipient_spk_priv32,
  };
  return recipient_opk_priv32
    ? x3dhResponderV1({ ...base, recipient_opk_priv32 })
    : x3dhResponderV1(base);
}

/**
 * Initiator helper that runs X3DH and derives the initial ratchet state using
 * the same X3DH ephemeral key as the initial sending DH key.
 */
export function x3dhInitiatorBootstrapV1(args: {
  sender_device_id: string;
  recipient_bundle: X3DHPrekeyBundleV1;
  initiator_ik_priv32: Uint8Array;
  initiator_ek_priv32?: Uint8Array;
  trust?: IdentityRegistry;
  allowRotateIdentity?: boolean;
}): {
  session_init: X3DHSessionInitV1;
  rk32: Uint8Array;
  ratchet_state: RatchetState;
  initiator_ek_priv32: Uint8Array;
} {
  const { trust, allowRotateIdentity, ...rest } = args;
  if (trust) {
    trust.trust(
      rest.recipient_bundle.recipient_device_id,
      rest.recipient_bundle.ik_pub_b64,
      allowRotateIdentity ? { allowRotate: true } : undefined
    );
  }

  const initiatorEkPriv32 = rest.initiator_ek_priv32 ?? generateX25519Keypair().priv32;
  const { session_init, rk32 } = x3dhInitiatorV1({
    ...rest,
    initiator_ek_priv32: initiatorEkPriv32,
  });

  const ekPub32 = x25519PublicFromPrivate(initiatorEkPriv32);
  const sessionEkPub32 = decodeX25519PubB64(session_init.ek_pub_b64, "session_init.ek_pub_b64");
  if (!timingSafeEqual(ekPub32, sessionEkPub32)) {
    throw new Error("session_init.ek_pub_b64 does not match initiator_ek_priv32");
  }

  const remoteDhPub32 = decodeX25519PubB64(
    rest.recipient_bundle.spk_pub_b64,
    "recipient_bundle.spk_pub_b64"
  );
  const ratchet_state = ratchetInit({
    rk32,
    selfDh: { priv32: initiatorEkPriv32, pub32: ekPub32 },
    remoteDhPub32,
    sendingFirst: true,
  });

  return {
    session_init,
    rk32,
    ratchet_state,
    initiator_ek_priv32: new Uint8Array(initiatorEkPriv32),
  };
}

/**
 * Responder helper that runs X3DH using prekey material and derives the initial
 * ratchet receiving state (self DH = selected SPK, remote DH = initiator EK).
 */
export function x3dhResponderBootstrapV1(args: {
  session_init: X3DHSessionInitV1;
  prekeys: X3DHPrekeyManagerV1;
  consumeOpk?: boolean;
  trust?: IdentityRegistry;
  allowRotateIdentity?: boolean;
}): { rk32: Uint8Array; ratchet_state: RatchetState } {
  const { session_init, prekeys } = args;
  const { rk32 } = x3dhResponderWithPrekeysV1(args);
  const recipientSpkPriv32 = prekeys.getSignedPrekeyPriv32(session_init.spk_id);
  const recipientSpkPub32 = x25519PublicFromPrivate(recipientSpkPriv32);
  const remoteDhPub32 = decodeX25519PubB64(session_init.ek_pub_b64, "session_init.ek_pub_b64");

  const ratchet_state = ratchetInit({
    rk32,
    selfDh: { priv32: recipientSpkPriv32, pub32: recipientSpkPub32 },
    remoteDhPub32,
    sendingFirst: false,
  });
  return { rk32, ratchet_state };
}

import type { X3DHPrekeyBundleV1, X3DHSessionInitV1 } from "../wire/x3dh.js";
import { x3dhInitiatorV1, x3dhResponderV1 } from "../crypto/x3dh.js";
import type { IdentityRegistry } from "../identity/trust.js";
import type { X3DHPrekeyManagerV1 } from "./prekey-manager.js";

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
}): { rk32: Uint8Array } {
  const { session_init, prekeys } = args;
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

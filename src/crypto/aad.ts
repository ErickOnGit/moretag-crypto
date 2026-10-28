/**
 * The per-message AAD (protocol v2): AD || H, the Double Ratchet's
 * CONCAT(AD, header) (DR §3.1, §3.4).
 *
 * H is one shortest-form CBOR array built from the header's decoded bytes:
 *
 *   H = [2, "xchacha20poly1305", nonce (bstr 24), dev_sender (bstr 16),
 *        dev_recipient (bstr 16), dh_pub (bstr 32), pn (uint), n (uint), grp]
 *   grp = null | [gid (bstr 16), epoch (uint)]
 *
 * Only these fields enter it, so no extra key of the JSON header (such as a
 * session_init sidecar) can. AD has a fixed length, so the concatenation needs no
 * length prefix.
 */

import { encodeCbor } from "../encoding/cbor.js";
import { decodeHeaderV2, type DecodedHeaderV2, type HeaderProtoV2 } from "../wire/header.js";
import { parseAssociatedDataV2 } from "./ad.js";
import { deviceIdToBytes } from "./device-id.js";

/** H for an already decoded header. */
export function encodeDecodedHeaderV2(h: DecodedHeaderV2): Uint8Array {
  return encodeCbor([
    2,
    "xchacha20poly1305",
    h.nonce24,
    deviceIdToBytes(h.sender_device_id),
    deviceIdToBytes(h.recipient_device_id),
    h.dh_pub32,
    h.pn,
    h.n,
    h.grp === null ? null : [deviceIdToBytes(h.grp.gid), h.grp.epoch],
  ]);
}

/** H for a wire header; the header is checked first (see decodeHeaderV2). */
export function encodeHeaderV2(header: HeaderProtoV2): Uint8Array {
  return encodeDecodedHeaderV2(decodeHeaderV2(header));
}

/** Throws TypeError unless `ad` is a well-formed 164-byte AD. */
export function assertAssociatedDataV2(ad: Uint8Array): void {
  parseAssociatedDataV2(ad);
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.byteLength + b.byteLength);
  out.set(a, 0);
  out.set(b, a.byteLength);
  return out;
}

/** AD || H for a decoded header; AD is checked. */
export function buildDeliveryAadFromDecodedV2(ad: Uint8Array, h: DecodedHeaderV2): Uint8Array {
  assertAssociatedDataV2(ad);
  return concat(ad, encodeDecodedHeaderV2(h));
}

/** The AAD of one message: AD || H. Both are checked first. */
export function buildDeliveryAadV2(ad: Uint8Array, header: HeaderProtoV2): Uint8Array {
  return buildDeliveryAadFromDecodedV2(ad, decodeHeaderV2(header));
}

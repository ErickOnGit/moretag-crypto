/**
 * Shortest-form CBOR (RFC 8949 §4.2.1) for the arrays the protocol signs or
 * authenticates: the signed-prekey message, the one-time prekey batch message, the
 * header array H and the self-seal AAD. Only these types are accepted: null,
 * unsigned safe integers, text strings, byte strings and arrays of them.
 *
 * cbor-x does the encoding, with two settings that keep it deterministic:
 * - tagUint8Array: false. cbor-x's Node build wraps a Uint8Array in CBOR tag 64
 *   while its browser and Hermes builds emit a plain byte string; without this a
 *   signature made on one platform would not verify on another (or the server).
 * - integers of 2^32 and above go in as BigInt. cbor-x writes a number above
 *   0xffffffff as a float64; a BigInt gives the 9-byte unsigned integer, which is
 *   the shortest form for those values.
 */

import { Encoder } from "cbor-x";

export type CborValue = null | number | string | Uint8Array | readonly CborValue[];

const ENCODER = new Encoder({
  mapsAsObjects: false,
  useRecords: false,
  tagUint8Array: false,
});

const UINT32_LIMIT = 0x1_0000_0000;

function normalize(value: CborValue): unknown {
  if (value === null || typeof value === "string" || value instanceof Uint8Array) return value;
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new TypeError("CBOR: only unsigned safe integers are encoded");
    }
    return value >= UINT32_LIMIT ? BigInt(value) : value;
  }
  if (Array.isArray(value)) return value.map(normalize);
  throw new TypeError("CBOR: unsupported value");
}

export function encodeCbor(value: CborValue): Uint8Array {
  return ENCODER.encode(normalize(value));
}

import { Encoder } from "cbor-x";
import type { HeaderProtoV1, ArchiveHeaderV1 } from "../wire/header.js";

/**
 * Global encoder instance for CBOR encoding.
 * - mapsAsObjects: false (we don't use Maps)
 * - useRecords: false (standard objects)
 */
const encoder = new Encoder({
  mapsAsObjects: false,
  useRecords: false,
});

const ENC = new TextEncoder();

function compareCanonicalKeys(a: string, b: string): number {
  const aBytes = ENC.encode(a);
  const bBytes = ENC.encode(b);

  if (aBytes.length !== bBytes.length) {
    return aBytes.length - bBytes.length;
  }

  const len = Math.min(aBytes.length, bBytes.length);
  for (let i = 0; i < len; i++) {
    const diff = (aBytes[i] ?? 0) - (bBytes[i] ?? 0);
    if (diff !== 0) return diff;
  }
  return 0;
}

/**
 * Recursively canonicalizes an object by sorting keys using CBOR canonical order
 * (shorter UTF-8 first, then bytewise lexicographic).
 * Only sorts keys for plain objects (Object.prototype or null prototype).
 * Non-plain objects (Uint8Array, Date, class instances) are preserved as-is.
 * Arrays and primitives are preserved (arrays have their elements canonicalized).
 * This ensures deterministic encoding regardless of key insertion order.
 */
function canonicalize(x: unknown): unknown {
  if (x === null || x === undefined) {
    return x;
  }

  if (Array.isArray(x)) {
    return x.map(canonicalize);
  }

  if (typeof x === "object") {
    // Preserve non-plain objects (Uint8Array, Date, class instances, etc.)
    const proto = Object.getPrototypeOf(x);
    if (proto !== Object.prototype && proto !== null) {
      return x;
    }

    // Plain object: sort keys lexicographically
    const obj = x as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    const sortedKeys = Object.keys(obj).sort(compareCanonicalKeys);
    for (const k of sortedKeys) {
      out[k] = canonicalize(obj[k]);
    }
    return out;
  }

  // Primitives (string, number, boolean, etc.)
  return x;
}

/**
 * Encodes the header (protocol or archive) into a deterministic/canonical byte sequence.
 * This byte sequence is used as AAD (Additional Authenticated Data) for encryption.
 *
 * AAD is authenticated but not encrypted.
 * We include the entire header structure exactly as provided.
 *
 * The canonicalization ensures deterministic encoding by:
 * - Sorting all object keys lexicographically
 * - Preserving array order
 * - Recursively applying canonicalization to nested structures
 */
export function encodeAADFromHeaderV1(
  header: HeaderProtoV1 | ArchiveHeaderV1
): Uint8Array {
  const canonical = canonicalize(header);
  return encoder.encode(canonical);
}

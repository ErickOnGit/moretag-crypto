/**
 * Branded type for UUID strings (v4 format expected).
 * Example: "550e8400-e29b-41d4-a716-446655440000"
 */
export type UUID = string & { readonly __brand: "UUID" };

/**
 * Branded type for base64-encoded strings.
 * Standard base64 encoding (RFC 4648).
 */
export type Base64String = string & { readonly __brand: "Base64String" };

// Re-export wire format types for convenience
export type { HeaderProtoV1, ArchiveHeaderV1 } from "./wire/header.js";
export type { MessagePayloadV1 } from "./wire/payload.js";

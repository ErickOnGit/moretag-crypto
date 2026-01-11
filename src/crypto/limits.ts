// Size and window limits to protect against resource exhaustion.

// Maximum plaintext size we will encrypt/decrypt (bytes). Allows space for tag/overhead.
export const MAX_PLAINTEXT_BYTES = 1_000_000; // ~1MB

// Maximum ciphertext size we will accept (bytes) after base64 decoding.
export const MAX_CIPHERTEXT_BYTES = 1_100_000; // ~1MB + tag/overhead

// Maximum number of skipped message keys retained.
export const MAX_SKIPPED_KEYS = 2000;

// Maximum derivation gap we allow when advancing a receive chain.
export const MAX_SKIP_DERIVE = 1000;

// Maximum UTF-8 byte length for device identifiers.
export const MAX_DEVICE_ID_BYTES = 256;

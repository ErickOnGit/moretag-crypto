const ENC = new TextEncoder();

/**
 * Validates a UTF-8 string is non-empty and within a max byte length.
 */
export function assertBoundedString(label: string, value: unknown, maxBytes: number): asserts value is string {
  if (typeof value !== "string" || value.length === 0) {
    throw new TypeError(`${label} must be a non-empty string`);
  }
  const bytes = ENC.encode(value);
  if (bytes.byteLength > maxBytes) {
    throw new TypeError(`${label} exceeds max length of ${maxBytes} bytes`);
  }
}

/**
 * Timing-safe equality check for two Uint8Arrays of equal length.
 */
export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false;
  let diff = 0;
  for (let i = 0; i < a.byteLength; i++) {
    diff |= a[i]! ^ b[i]!;
  }
  return diff === 0;
}

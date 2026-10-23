/**
 * Shared test fixtures (not part of the build): canonical UUID device ids.
 */

export const ALICE_DEVICE = "0f0e5a3c-6b1d-4c2e-8a7f-1d2c3b4a5f60";
export const BOB_DEVICE = "4b8d2e6f-0a1c-4e3d-9b5a-7c6d5e4f3a21";
export const CAROL_DEVICE = "9a7c5e3b-1d2f-4a6b-8c0e-2f4a6c8e0b13";

export const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);

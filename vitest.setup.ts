import { webcrypto } from "node:crypto";

// Make Web Crypto API available globally for tests
if (!globalThis.crypto) {
  // @ts-expect-error - Node.js webcrypto is compatible
  globalThis.crypto = webcrypto;
}

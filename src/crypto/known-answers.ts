/**
 * Published known-answer constants, copied from the public texts by hand.
 * registerCryptoPrimitives() checks a provider against them, and the tests check
 * the built-in @noble implementations too.
 */

function hex(s: string): Uint8Array {
  const clean = s.replace(/\s+/g, "");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(2 * i, 2 * i + 2), 16);
  return out;
}

/** RFC 7748 §6.1 (Curve25519 Diffie-Hellman). Private keys as printed, before clamping. */
export const RFC7748_6_1 = {
  alicePriv: hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"),
  alicePub: hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"),
  bobPriv: hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"),
  bobPub: hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"),
  shared: hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"),
} as const;

/** RFC 8032 §7.1, TEST 1 (Ed25519, empty message). */
export const RFC8032_7_1_TEST1 = {
  seed: hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"),
  pub: hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"),
  message: new Uint8Array(0),
  sig: hex(
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
  ),
} as const;

/** RFC 5869 Appendix A.1 (HKDF-SHA256, basic test case). */
export const RFC5869_A1 = {
  ikm: hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
  salt: hex("000102030405060708090a0b0c"),
  info: hex("f0f1f2f3f4f5f6f7f8f9"),
  okm: hex(
    "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
  ),
} as const;

/** RFC 5869 Appendix A.3 (HKDF-SHA256, zero-length salt and info). */
export const RFC5869_A3 = {
  ikm: hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
  salt: new Uint8Array(0),
  info: new Uint8Array(0),
  okm: hex(
    "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
  ),
} as const;

/** draft-irtf-cfrg-xchacha-03 Appendix A.3.1 (AEAD_XChaCha20_Poly1305). */
export const XCHACHA_DRAFT03_A3_1 = {
  plaintext: new TextEncoder().encode(
    "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
  ),
  aad: hex("50515253c0c1c2c3c4c5c6c7"),
  key: hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"),
  nonce: hex("404142434445464748494a4b4c4d4e4f5051525354555657"),
  /** Ciphertext followed by the 16-byte tag. */
  sealed: hex(
    "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb" +
      "731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452" +
      "2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9" +
      "21f9664c97637da9768812f615c68b13b52e" +
      "c0875924c1c7987947deafd8780acf49"
  ),
} as const;

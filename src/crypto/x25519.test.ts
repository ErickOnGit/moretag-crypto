import { test, expect, afterEach } from "vitest";
import {
  generateX25519Keypair,
  x25519PublicFromPrivate,
  x25519SharedSecret,
} from "./x25519.js";
import { getPrimitives, registerCryptoPrimitives, resetCryptoPrimitives } from "./primitives.js";
import { LowOrderKeyError } from "../errors.js";

afterEach(() => {
  resetCryptoPrimitives();
});

/** Low-order u-coordinates: every scalar maps them to the all-zero secret. */
const U0 = new Uint8Array(32);
const U1 = Uint8Array.from({ length: 32 }, (_, i) => (i === 0 ? 1 : 0));

test("Alice and Bob shared secrets match", () => {
  // Alice generates her keypair
  const alice = generateX25519Keypair();

  // Bob generates his keypair
  const bob = generateX25519Keypair();

  // Alice computes shared secret using her private key and Bob's public key
  const aliceShared = x25519SharedSecret(alice.priv32, bob.pub32);

  // Bob computes shared secret using his private key and Alice's public key
  const bobShared = x25519SharedSecret(bob.priv32, alice.pub32);

  // Shared secrets should match
  expect(aliceShared).toEqual(bobShared);
  expect(aliceShared.byteLength).toBe(32);
});

test("different public key produces different shared secret", () => {
  const alice = generateX25519Keypair();
  const bob = generateX25519Keypair();
  const charlie = generateX25519Keypair();

  // Shared secret with Bob
  const secretBob = x25519SharedSecret(alice.priv32, bob.pub32);

  // Shared secret with Charlie
  const secretCharlie = x25519SharedSecret(alice.priv32, charlie.pub32);

  // Secrets should be different
  expect(secretBob).not.toEqual(secretCharlie);
});

test("x25519SharedSecret enforces 32-byte private key length", () => {
  const alice = generateX25519Keypair();
  const shortPriv = new Uint8Array(31);

  expect(() => x25519SharedSecret(shortPriv, alice.pub32)).toThrowError(
    /Invalid private key length.*expected 32 bytes, got 31/
  );
});

test("x25519SharedSecret enforces 32-byte public key length", () => {
  const alice = generateX25519Keypair();
  const shortPub = new Uint8Array(31);

  expect(() => x25519SharedSecret(alice.priv32, shortPub)).toThrowError(
    /Invalid public key length.*expected 32 bytes, got 31/
  );
});

test("generateX25519Keypair produces 32-byte keys", () => {
  const keypair = generateX25519Keypair();

  expect(keypair.priv32.byteLength).toBe(32);
  expect(keypair.pub32.byteLength).toBe(32);
});

test("generateX25519Keypair produces different keys each time", () => {
  const keypair1 = generateX25519Keypair();
  const keypair2 = generateX25519Keypair();

  expect(keypair1.priv32).not.toEqual(keypair2.priv32);
  expect(keypair1.pub32).not.toEqual(keypair2.pub32);
});

test("x25519PublicFromPrivate matches generated keypair public key", () => {
  const keypair = generateX25519Keypair();
  const pub = x25519PublicFromPrivate(keypair.priv32);
  expect(pub).toEqual(keypair.pub32);
});

test("x25519PublicFromPrivate enforces 32-byte private key length", () => {
  expect(() => x25519PublicFromPrivate(new Uint8Array(31))).toThrowError(
    /Invalid private key length.*expected 32 bytes, got 31/
  );
});

test("u=0 and u=1 are refused", () => {
  const priv = generateX25519Keypair().priv32;
  expect(() => x25519SharedSecret(priv, U0)).toThrow(LowOrderKeyError);
  expect(() => x25519SharedSecret(priv, U1)).toThrow(LowOrderKeyError);
});

test("an all-zero secret from a backend that does not refuse it is refused here", () => {
  const noble = getPrimitives();
  const lowOrder = (pub: Uint8Array) => (pub[0] ?? 0) <= 1 && pub.subarray(1).every((b) => b === 0);
  registerCryptoPrimitives({
    name: "returns-zeros",
    randomBytes: noble.randomBytes,
    x25519SharedSecret: (priv, pub) => (lowOrder(pub) ? new Uint8Array(32) : noble.x25519SharedSecret(priv, pub)),
  });
  const priv = generateX25519Keypair().priv32;
  for (const u of [U0, U1]) {
    expect(() => x25519SharedSecret(priv, u)).toThrow(LowOrderKeyError);
  }
});

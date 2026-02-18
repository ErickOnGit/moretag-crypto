import { test, expect } from "vitest";
import {
  generateX25519Keypair,
  x25519PublicFromPrivate,
  x25519SharedSecret,
} from "./x25519.js";

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

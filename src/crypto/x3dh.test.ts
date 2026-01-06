/**
 * Tests for X3DH v1 session initialization with signed prekey verification.
 */

import { describe, it, expect } from "vitest";
import type {
  X3DHPrekeyBundleV1,
  X3DHSessionInitV1,
} from "../wire/x3dh.js";
import {
  decodeX25519PubB64,
  x3dhInitiatorV1,
  x3dhResponderV1,
} from "./x3dh.js";
import { generateX25519Keypair } from "./x25519.js";
import { generateEd25519Keypair, ed25519Sign } from "./ed25519.js";
import { bytesToBase64 } from "../encoding/base64.js";

describe("X3DH v1", () => {
  // Helper to create a signed prekey bundle
  function createSignedBundle(args: {
    recipient_device_id: string;
    recipient_ik: ReturnType<typeof generateX25519Keypair>;
    recipient_spk: ReturnType<typeof generateX25519Keypair>;
    recipient_ik_sig: ReturnType<typeof generateEd25519Keypair>;
    spk_id: number | string;
    opk?: ReturnType<typeof generateX25519Keypair>;
    opk_id?: number | string;
  }): X3DHPrekeyBundleV1 {
    const { recipient_device_id, recipient_ik, recipient_spk, recipient_ik_sig, spk_id, opk, opk_id } = args;

    // Build signature message: "moretag/x3dh/spk/v1" || device_id || ik_pub || spk_pub || spk_id
    const ENC = new TextEncoder();
    const domain = ENC.encode("moretag/x3dh/spk/v1");
    const dev = ENC.encode(recipient_device_id);
    const spkIdBytes = ENC.encode(String(spk_id));
    
    const sigMsg = new Uint8Array(
      domain.length + dev.length + recipient_ik.pub32.length + recipient_spk.pub32.length + spkIdBytes.length
    );
    let off = 0;
    sigMsg.set(domain, off); off += domain.length;
    sigMsg.set(dev, off); off += dev.length;
    sigMsg.set(recipient_ik.pub32, off); off += recipient_ik.pub32.length;
    sigMsg.set(recipient_spk.pub32, off); off += recipient_spk.pub32.length;
    sigMsg.set(spkIdBytes, off);

    const spk_sig = ed25519Sign(recipient_ik_sig.priv32, sigMsg);

    const bundle: X3DHPrekeyBundleV1 = {
      v: 1,
      alg: "x3dh-x25519-hkdf-sha256+ed25519",
      recipient_device_id,
      ik_pub_b64: bytesToBase64(recipient_ik.pub32),
      spk_pub_b64: bytesToBase64(recipient_spk.pub32),
      spk_sig_b64: bytesToBase64(spk_sig),
      ik_sig_pub_b64: bytesToBase64(recipient_ik_sig.pub32),
      spk_id,
    };

    if (opk && opk_id !== undefined) {
      bundle.opk_pub_b64 = bytesToBase64(opk.pub32);
      bundle.opk_id = opk_id;
    }

    return bundle;
  }

  describe("decodeX25519PubB64", () => {
    it("should decode valid 32-byte base64", () => {
      const key = new Uint8Array(32).fill(42);
      const b64 = bytesToBase64(key);
      const decoded = decodeX25519PubB64(b64, "test_key");
      expect(decoded).toEqual(key);
    });

    it("should throw TypeError on wrong decoded length", () => {
      const key = new Uint8Array(16); // Wrong length
      const b64 = bytesToBase64(key);
      expect(() => decodeX25519PubB64(b64, "test_key")).toThrow(TypeError);
      expect(() => decodeX25519PubB64(b64, "test_key"))
        .toThrow("Invalid test_key length: expected 32 bytes, got 16");
    });
  });

  describe("initiator/responder agreement", () => {
    it("should compute matching rk32 without OPK", () => {
      // Generate recipient keys
      const recipient_ik = generateX25519Keypair();
      const recipient_spk = generateX25519Keypair();
      const recipient_ik_sig = generateEd25519Keypair();

      const bundle = createSignedBundle({
        recipient_device_id: "bob-device-1",
        recipient_ik,
        recipient_spk,
        recipient_ik_sig,
        spk_id: 100,
      });

      // Generate initiator keys
      const initiator_ik = generateX25519Keypair();
      const initiator_ek = generateX25519Keypair();

      // Initiator computes session
      const initResult = x3dhInitiatorV1({
        sender_device_id: "alice-device-1",
        recipient_bundle: bundle,
        initiator_ik_priv32: initiator_ik.priv32,
        initiator_ek_priv32: initiator_ek.priv32,
      });

      expect(initResult.session_init.used_opk).toBe(false);
      expect(initResult.session_init.spk_id).toBe(100);
      expect(initResult.session_init.opk_id).toBeUndefined();

      // Responder computes session
      const respResult = x3dhResponderV1({
        session_init: initResult.session_init,
        recipient_ik_priv32: recipient_ik.priv32,
        recipient_spk_priv32: recipient_spk.priv32,
      });

      // Both should compute the same rk32
      expect(respResult.rk32).toEqual(initResult.rk32);
      expect(initResult.rk32.byteLength).toBe(32);
    });

    it("should compute matching rk32 with OPK", () => {
      // Generate recipient keys including OPK
      const recipient_ik = generateX25519Keypair();
      const recipient_spk = generateX25519Keypair();
      const recipient_opk = generateX25519Keypair();
      const recipient_ik_sig = generateEd25519Keypair();

      const bundle = createSignedBundle({
        recipient_device_id: "bob-device-1",
        recipient_ik,
        recipient_spk,
        recipient_ik_sig,
        spk_id: 100,
        opk: recipient_opk,
        opk_id: 42,
      });

      // Generate initiator keys
      const initiator_ik = generateX25519Keypair();
      const initiator_ek = generateX25519Keypair();

      // Initiator computes session
      const initResult = x3dhInitiatorV1({
        sender_device_id: "alice-device-1",
        recipient_bundle: bundle,
        initiator_ik_priv32: initiator_ik.priv32,
        initiator_ek_priv32: initiator_ek.priv32,
      });

      expect(initResult.session_init.used_opk).toBe(true);
      expect(initResult.session_init.spk_id).toBe(100);
      expect(initResult.session_init.opk_id).toBe(42);

      // Responder computes session with OPK
      const respResult = x3dhResponderV1({
        session_init: initResult.session_init,
        recipient_ik_priv32: recipient_ik.priv32,
        recipient_spk_priv32: recipient_spk.priv32,
        recipient_opk_priv32: recipient_opk.priv32,
      });

      // Both should compute the same rk32
      expect(respResult.rk32).toEqual(initResult.rk32);
      expect(initResult.rk32.byteLength).toBe(32);
    });

    it("should generate ephemeral key if not provided", () => {
      const recipient_ik = generateX25519Keypair();
      const recipient_spk = generateX25519Keypair();
      const recipient_ik_sig = generateEd25519Keypair();

      const bundle = createSignedBundle({
        recipient_device_id: "bob-device-1",
        recipient_ik,
        recipient_spk,
        recipient_ik_sig,
        spk_id: 100,
      });

      const initiator_ik = generateX25519Keypair();

      // Don't provide initiator_ek_priv32
      const initResult = x3dhInitiatorV1({
        sender_device_id: "alice-device-1",
        recipient_bundle: bundle,
        initiator_ik_priv32: initiator_ik.priv32,
      });

      expect(initResult.rk32.byteLength).toBe(32);
      expect(initResult.session_init.ek_pub_b64).toBeTruthy();

      // Verify responder can still compute matching key
      const respResult = x3dhResponderV1({
        session_init: initResult.session_init,
        recipient_ik_priv32: recipient_ik.priv32,
        recipient_spk_priv32: recipient_spk.priv32,
      });

      expect(respResult.rk32).toEqual(initResult.rk32);
    });
  });

  describe("signature verification", () => {
    it("should reject invalid SPK signature", () => {
      const recipient_ik = generateX25519Keypair();
      const recipient_spk = generateX25519Keypair();
      const recipient_ik_sig = generateEd25519Keypair();

      // Sign with wrong message
      const wrongMsg = new Uint8Array(64).fill(0xff);
      const wrongSig = ed25519Sign(recipient_ik_sig.priv32, wrongMsg);

      const bundle: X3DHPrekeyBundleV1 = {
        v: 1,
        alg: "x3dh-x25519-hkdf-sha256+ed25519",
        recipient_device_id: "bob-device-1",
        ik_pub_b64: bytesToBase64(recipient_ik.pub32),
        spk_pub_b64: bytesToBase64(recipient_spk.pub32),
        spk_sig_b64: bytesToBase64(wrongSig),
        ik_sig_pub_b64: bytesToBase64(recipient_ik_sig.pub32),
        spk_id: 100,
      };

      const initiator_ik = generateX25519Keypair();

      expect(() =>
        x3dhInitiatorV1({
          sender_device_id: "alice-device-1",
          recipient_bundle: bundle,
          initiator_ik_priv32: initiator_ik.priv32,
        })
      ).toThrow(TypeError);
      expect(() =>
        x3dhInitiatorV1({
          sender_device_id: "alice-device-1",
          recipient_bundle: bundle,
          initiator_ik_priv32: initiator_ik.priv32,
        })
      ).toThrow("Invalid spk_sig_b64: signature verification failed");
    });

    it("should reject if spk_sig is signed by wrong key", () => {
      const recipient_ik = generateX25519Keypair();
      const recipient_spk = generateX25519Keypair();
      const recipient_ik_sig = generateEd25519Keypair();
      const wrongSigKey = generateEd25519Keypair();

      // Build correct message but sign with wrong key
      const ENC = new TextEncoder();
      const domain = ENC.encode("moretag/x3dh/spk/v1");
      const dev = ENC.encode("bob-device-1");
      const spkIdBytes = ENC.encode("100");
      
      const sigMsg = new Uint8Array(
        domain.length + dev.length + recipient_ik.pub32.length + recipient_spk.pub32.length + spkIdBytes.length
      );
      let off = 0;
      sigMsg.set(domain, off); off += domain.length;
      sigMsg.set(dev, off); off += dev.length;
      sigMsg.set(recipient_ik.pub32, off); off += recipient_ik.pub32.length;
      sigMsg.set(recipient_spk.pub32, off); off += recipient_spk.pub32.length;
      sigMsg.set(spkIdBytes, off);

      const wrongSig = ed25519Sign(wrongSigKey.priv32, sigMsg);

      const bundle: X3DHPrekeyBundleV1 = {
        v: 1,
        alg: "x3dh-x25519-hkdf-sha256+ed25519",
        recipient_device_id: "bob-device-1",
        ik_pub_b64: bytesToBase64(recipient_ik.pub32),
        spk_pub_b64: bytesToBase64(recipient_spk.pub32),
        spk_sig_b64: bytesToBase64(wrongSig),
        ik_sig_pub_b64: bytesToBase64(recipient_ik_sig.pub32),
        spk_id: 100,
      };

      const initiator_ik = generateX25519Keypair();

      expect(() =>
        x3dhInitiatorV1({
          sender_device_id: "alice-device-1",
          recipient_bundle: bundle,
          initiator_ik_priv32: initiator_ik.priv32,
        })
      ).toThrow(TypeError);
    });

    it("should reject if signature was created with different spk_id", () => {
      const recipient_ik = generateX25519Keypair();
      const recipient_spk = generateX25519Keypair();
      const recipient_ik_sig = generateEd25519Keypair();

      // Create bundle with spk_id 100, but signature was for spk_id 999
      const bundleWithWrongId = createSignedBundle({
        recipient_device_id: "bob-device-1",
        recipient_ik,
        recipient_spk,
        recipient_ik_sig,
        spk_id: 999, // Signature created with this ID
      });

      // Change the spk_id after signing
      bundleWithWrongId.spk_id = 100;

      const initiator_ik = generateX25519Keypair();

      expect(() =>
        x3dhInitiatorV1({
          sender_device_id: "alice-device-1",
          recipient_bundle: bundleWithWrongId,
          initiator_ik_priv32: initiator_ik.priv32,
        })
      ).toThrow("Invalid spk_sig_b64: signature verification failed");
    });
  });

  describe("length enforcement", () => {
    it("should throw TypeError for invalid initiator_ik_priv32 length", () => {
      const recipient_ik = generateX25519Keypair();
      const recipient_spk = generateX25519Keypair();
      const recipient_ik_sig = generateEd25519Keypair();

      const bundle = createSignedBundle({
        recipient_device_id: "bob-device-1",
        recipient_ik,
        recipient_spk,
        recipient_ik_sig,
        spk_id: 100,
      });

      expect(() =>
        x3dhInitiatorV1({
          sender_device_id: "alice-device-1",
          recipient_bundle: bundle,
          initiator_ik_priv32: new Uint8Array(16), // Wrong length
        })
      ).toThrow(TypeError);
      expect(() =>
        x3dhInitiatorV1({
          sender_device_id: "alice-device-1",
          recipient_bundle: bundle,
          initiator_ik_priv32: new Uint8Array(16),
        })
      ).toThrow("Invalid initiator_ik_priv32 length: expected 32 bytes, got 16");
    });

    it("should throw TypeError for invalid spk_sig_b64 length", () => {
      const recipient_ik = generateX25519Keypair();
      const recipient_spk = generateX25519Keypair();
      const recipient_ik_sig = generateEd25519Keypair();

      const bundle: X3DHPrekeyBundleV1 = {
        v: 1,
        alg: "x3dh-x25519-hkdf-sha256+ed25519",
        recipient_device_id: "bob-device-1",
        ik_pub_b64: bytesToBase64(recipient_ik.pub32),
        spk_pub_b64: bytesToBase64(recipient_spk.pub32),
        spk_sig_b64: bytesToBase64(new Uint8Array(32)), // Wrong length (should be 64)
        ik_sig_pub_b64: bytesToBase64(recipient_ik_sig.pub32),
        spk_id: 100,
      };

      const initiator_ik = generateX25519Keypair();

      expect(() =>
        x3dhInitiatorV1({
          sender_device_id: "alice-device-1",
          recipient_bundle: bundle,
          initiator_ik_priv32: initiator_ik.priv32,
        })
      ).toThrow(TypeError);
      expect(() =>
        x3dhInitiatorV1({
          sender_device_id: "alice-device-1",
          recipient_bundle: bundle,
          initiator_ik_priv32: initiator_ik.priv32,
        })
      ).toThrow("Invalid spk_sig_b64 length: expected 64 bytes, got 32");
    });

    it("should throw TypeError for invalid ik_sig_pub_b64 length", () => {
      const recipient_ik = generateX25519Keypair();
      const recipient_spk = generateX25519Keypair();

      const bundle: X3DHPrekeyBundleV1 = {
        v: 1,
        alg: "x3dh-x25519-hkdf-sha256+ed25519",
        recipient_device_id: "bob-device-1",
        ik_pub_b64: bytesToBase64(recipient_ik.pub32),
        spk_pub_b64: bytesToBase64(recipient_spk.pub32),
        spk_sig_b64: bytesToBase64(new Uint8Array(64)),
        ik_sig_pub_b64: bytesToBase64(new Uint8Array(16)), // Wrong length
        spk_id: 100,
      };

      const initiator_ik = generateX25519Keypair();

      expect(() =>
        x3dhInitiatorV1({
          sender_device_id: "alice-device-1",
          recipient_bundle: bundle,
          initiator_ik_priv32: initiator_ik.priv32,
        })
      ).toThrow(TypeError);
      expect(() =>
        x3dhInitiatorV1({
          sender_device_id: "alice-device-1",
          recipient_bundle: bundle,
          initiator_ik_priv32: initiator_ik.priv32,
        })
      ).toThrow("Invalid ik_sig_pub_b64 length: expected 32 bytes, got 16");
    });
  });

  describe("OPK identification", () => {
    it("should include opk_id in session_init when OPK is used", () => {
      const recipient_ik = generateX25519Keypair();
      const recipient_spk = generateX25519Keypair();
      const recipient_opk = generateX25519Keypair();
      const recipient_ik_sig = generateEd25519Keypair();

      const bundle = createSignedBundle({
        recipient_device_id: "bob-device-1",
        recipient_ik,
        recipient_spk,
        recipient_ik_sig,
        spk_id: 100,
        opk: recipient_opk,
        opk_id: "opk-12345",
      });

      const initiator_ik = generateX25519Keypair();

      const initResult = x3dhInitiatorV1({
        sender_device_id: "alice-device-1",
        recipient_bundle: bundle,
        initiator_ik_priv32: initiator_ik.priv32,
      });

      expect(initResult.session_init.used_opk).toBe(true);
      expect(initResult.session_init.opk_id).toBe("opk-12345");
    });

    it("should not include opk_id when OPK is not used", () => {
      const recipient_ik = generateX25519Keypair();
      const recipient_spk = generateX25519Keypair();
      const recipient_ik_sig = generateEd25519Keypair();

      const bundle = createSignedBundle({
        recipient_device_id: "bob-device-1",
        recipient_ik,
        recipient_spk,
        recipient_ik_sig,
        spk_id: 100,
      });

      const initiator_ik = generateX25519Keypair();

      const initResult = x3dhInitiatorV1({
        sender_device_id: "alice-device-1",
        recipient_bundle: bundle,
        initiator_ik_priv32: initiator_ik.priv32,
      });

      expect(initResult.session_init.used_opk).toBe(false);
      expect(initResult.session_init.opk_id).toBeUndefined();
    });

    it("should require opk_id in bundle when opk_pub_b64 is present", () => {
      const recipient_ik = generateX25519Keypair();
      const recipient_spk = generateX25519Keypair();
      const recipient_opk = generateX25519Keypair();
      const recipient_ik_sig = generateEd25519Keypair();

      const bundle = createSignedBundle({
        recipient_device_id: "bob-device-1",
        recipient_ik,
        recipient_spk,
        recipient_ik_sig,
        spk_id: 100,
        opk: recipient_opk,
        opk_id: 42,
      });

      // Remove opk_id after creating bundle
      delete bundle.opk_id;

      const initiator_ik = generateX25519Keypair();

      expect(() =>
        x3dhInitiatorV1({
          sender_device_id: "alice-device-1",
          recipient_bundle: bundle,
          initiator_ik_priv32: initiator_ik.priv32,
        })
      ).toThrow("opk_id is required when opk_pub_b64 is provided");
    });

    it("should require opk_id in session_init when responder has used_opk=true", () => {
      const session_init: X3DHSessionInitV1 = {
        v: 1,
        alg: "x3dh-x25519-hkdf-sha256+ed25519",
        sender_device_id: "alice-device-1",
        sender_ik_pub_b64: bytesToBase64(new Uint8Array(32)),
        ek_pub_b64: bytesToBase64(new Uint8Array(32)),
        recipient_device_id: "bob-device-1",
        spk_id: 100,
        used_opk: true,
        // Missing opk_id
      };

      const recipient_ik = generateX25519Keypair();
      const recipient_spk = generateX25519Keypair();
      const recipient_opk = generateX25519Keypair();

      expect(() =>
        x3dhResponderV1({
          session_init,
          recipient_ik_priv32: recipient_ik.priv32,
          recipient_spk_priv32: recipient_spk.priv32,
          recipient_opk_priv32: recipient_opk.priv32,
        })
      ).toThrow(TypeError);
      expect(() =>
        x3dhResponderV1({
          session_init,
          recipient_ik_priv32: recipient_ik.priv32,
          recipient_spk_priv32: recipient_spk.priv32,
          recipient_opk_priv32: recipient_opk.priv32,
        })
      ).toThrow("opk_id is required in session_init when used_opk is true");
    });
  });

  describe("determinism", () => {
    it("should produce same rk32 with same inputs", () => {
      const recipient_ik = generateX25519Keypair();
      const recipient_spk = generateX25519Keypair();
      const recipient_ik_sig = generateEd25519Keypair();
      const initiator_ik = generateX25519Keypair();
      const initiator_ek = generateX25519Keypair();

      const bundle = createSignedBundle({
        recipient_device_id: "bob-device-1",
        recipient_ik,
        recipient_spk,
        recipient_ik_sig,
        spk_id: 100,
      });

      const result1 = x3dhInitiatorV1({
        sender_device_id: "alice-device-1",
        recipient_bundle: bundle,
        initiator_ik_priv32: initiator_ik.priv32,
        initiator_ek_priv32: initiator_ek.priv32,
      });

      const result2 = x3dhInitiatorV1({
        sender_device_id: "alice-device-1",
        recipient_bundle: bundle,
        initiator_ik_priv32: initiator_ik.priv32,
        initiator_ek_priv32: initiator_ek.priv32,
      });

      expect(result2.rk32).toEqual(result1.rk32);
    });
  });

  describe("tampering detection", () => {
    it("should produce different rk32 if SPK is tampered", () => {
      const recipient_ik = generateX25519Keypair();
      const recipient_spk = generateX25519Keypair();
      const recipient_ik_sig = generateEd25519Keypair();
      const initiator_ik = generateX25519Keypair();

      const bundle = createSignedBundle({
        recipient_device_id: "bob-device-1",
        recipient_ik,
        recipient_spk,
        recipient_ik_sig,
        spk_id: 100,
      });

      // Tamper with SPK after signing
      const tamperedSpk = new Uint8Array(recipient_spk.pub32);
      if (tamperedSpk.length > 0) {
        const lastIdx = tamperedSpk.length - 1;
        const lastByte = tamperedSpk[lastIdx];
        if (lastByte !== undefined) {
          tamperedSpk[lastIdx] = lastByte ^ 1;
        }
      }
      bundle.spk_pub_b64 = bytesToBase64(tamperedSpk);

      // Should fail signature verification
      expect(() =>
        x3dhInitiatorV1({
          sender_device_id: "alice-device-1",
          recipient_bundle: bundle,
          initiator_ik_priv32: initiator_ik.priv32,
        })
      ).toThrow("Invalid spk_sig_b64: signature verification failed");
    });
  });
});

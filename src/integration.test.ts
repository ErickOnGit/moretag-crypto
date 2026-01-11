/**
 * End-to-End Integration Test
 *
 * Demonstrates complete flow from identity generation through message encryption,
 * persistence, reload, out-of-order delivery, and replay prevention.
 *
 * Note: This test uses manual state management and explicit version tracking for clarity.
 * Future enhancement: Consider using ratchetEncryptWithStore/ratchetDecryptWithStore wrappers
 * to more realistically exercise store-level transaction semantics and version monotonicity.
 */

import { describe, it, expect } from "vitest";
import { mkdtempSync, rmSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { randomBytes } from "@noble/ciphers/utils.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { X3DHPrekeyManagerV1 } from "./x3dh/prekey-manager.js";
import { x3dhInitiatorV1 } from "./crypto/x3dh.js";
import { x3dhResponderWithPrekeysV1 } from "./x3dh/session.js";
import { ratchetInit, ratchetEncrypt, ratchetDecrypt } from "./ratchet/ratchet.js";
import { FileRatchetStore } from "./ratchet/file-store.js";
import { createPersistedSession, type PersistedSession } from "./ratchet/session-store.js";
import { base64ToBytes } from "./encoding/base64.js";
import type { RatchetState } from "./ratchet/ratchet.js";

function encode(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

function nextVersion(record?: PersistedSession): number {
  return record ? record.version + 1 : 0;
}

function saveNext(store: FileRatchetStore, sessionId: string, state: RatchetState): void {
  const current = store.load(sessionId);
  store.save(sessionId, { version: nextVersion(current), state });
}

/**
 * Helper function for session ID generation (demonstrates best practice).
 * Uses SHA-256 hash of device IDs and direction to create deterministic,
 * collision-resistant session identifiers.
 */
function computeSessionId(
  myDeviceId: string,
  theirDeviceId: string,
  direction: "send" | "recv"
): string {
  const data = `${myDeviceId}||${theirDeviceId}||${direction}`;
  const hash = sha256(new TextEncoder().encode(data));
  return Array.from(hash)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

describe("End-to-End Integration", () => {
  it("complete flow: X3DH → ratchet → persist → reload → out-of-order → replay", () => {
    // Setup temp directory for file store
    const storeDir = mkdtempSync(join(tmpdir(), "integration-"));

    try {
      // =====================================================================
      // Step 1: Identity and Prekey Generation (both Alice and Bob)
      // =====================================================================
      const alice = new X3DHPrekeyManagerV1({
        recipient_device_id: "alice-device-001",
      });
      const bob = new X3DHPrekeyManagerV1({
        recipient_device_id: "bob-device-001",
      });

      // =====================================================================
      // Step 2: Bob publishes prekey bundle
      // =====================================================================
      bob.rotateSignedPrekey(Date.now());
      bob.addOneTimePrekeys({ startId: 1, count: 10 });
      const bobBundle = bob.getPrekeyBundle();

      // Verify bundle structure
      expect(bobBundle.v).toBe(1);
      expect(bobBundle.recipient_device_id).toBe("bob-device-001");
      expect(bobBundle.opk_pub_b64).toBeDefined(); // Should have OPK

      // =====================================================================
      // Step 3: Session Initialization (Alice initiates with Bob's bundle)
      // =====================================================================
      const { session_init, rk32 } = x3dhInitiatorV1({
        sender_device_id: alice.recipient_device_id,
        recipient_bundle: bobBundle,
        initiator_ik_priv32: alice.ik.priv32,
      });

      // Verify session init structure
      expect(session_init.v).toBe(1);
      expect(session_init.sender_device_id).toBe("alice-device-001");
      expect(session_init.recipient_device_id).toBe("bob-device-001");
      expect(session_init.used_opk).toBe(true);
      expect(rk32.byteLength).toBe(32);

      // =====================================================================
      // Step 4-5: Initialize ratchet states for both parties
      // =====================================================================
      // For Double Ratchet initialization after X3DH:
      // - Bob uses his signed prekey as his initial DH keypair
      // - Alice uses Bob's SPK public key as the remote DH key
      // - Bob will learn Alice's DH public key from the first message header

      // Alice initializes her sending state with Bob's SPK as remote DH key
      const bobSpkPub32 = base64ToBytes(bobBundle.spk_pub_b64);
      const aliceState = ratchetInit({
        rk32,
        remoteDhPub32: bobSpkPub32, // Use Bob's signed prekey
        sendingFirst: true,
      });

      // Bob responds and initializes his receiving state
      const bobResp = x3dhResponderWithPrekeysV1({
        session_init,
        prekeys: bob,
        consumeOpk: true, // Consume the one-time prekey
      });

      // Verify both derived same root key
      expect(bobResp.rk32).toEqual(rk32);

      // Bob uses his SPK as his initial DH keypair, and will learn Alice's DH key from the header
      const bobState = ratchetInit({
        rk32: bobResp.rk32,
        selfDh: { priv32: bob.getSignedPrekeyPriv32(bobBundle.spk_id), pub32: bobSpkPub32 },
        remoteDhPub32: aliceState.dh_self.pub32, // Use Alice's DH public key
        sendingFirst: false,
      });

      // =====================================================================
      // Step 6: Persist session state to FileRatchetStore
      // =====================================================================
      const macKey = randomBytes(32);
      const store = new FileRatchetStore(storeDir, { macKey32: macKey });

      // Generate session IDs using deterministic scheme
      const aliceSessionId = computeSessionId(
        alice.recipient_device_id,
        bob.recipient_device_id,
        "send"
      );
      const bobSessionId = computeSessionId(
        bob.recipient_device_id,
        alice.recipient_device_id,
        "recv"
      );

      // Verify session IDs are deterministic and different per direction
      expect(aliceSessionId).toBe(
        computeSessionId("alice-device-001", "bob-device-001", "send")
      );
      expect(aliceSessionId).not.toBe(bobSessionId);

      // Save initial states with version 0
      // FileRatchetStore enforces monotonic version increments to prevent rollback attacks
      store.save(aliceSessionId, createPersistedSession(aliceState));
      store.save(bobSessionId, createPersistedSession(bobState));

      // =====================================================================
      // Step 7: Encrypt initial message (Alice encrypts "hello")
      // =====================================================================
      // First message uses in-memory state to verify setup is correct
      const { header: h1, ciphertext_b64: c1 } = ratchetEncrypt({
        state: aliceState,
        plaintext: encode("hello"),
        sender_device_id: alice.recipient_device_id,
        recipient_device_id: bob.recipient_device_id,
      });

      // Verify header structure
      expect(h1.v).toBe(1);
      expect(h1.alg).toBe("xchacha20poly1305");
      expect(h1.sender_device_id).toBe("alice-device-001");
      expect(h1.recipient_device_id).toBe("bob-device-001");
      expect(h1.dr.n).toBe(0); // First message in chain

      // Save Alice's updated state with explicit version increment
      saveNext(store, aliceSessionId, aliceState);

      // =====================================================================
      // Step 8: Successful Decryption (Bob decrypts)
      // =====================================================================
      // First message uses in-memory state to verify setup is correct
      const { plaintext: p1 } = ratchetDecrypt({
        state: bobState,
        header: h1,
        ciphertext_b64: c1,
      });

      expect(new TextDecoder().decode(p1)).toBe("hello");

      // Save Bob's updated state with explicit version increment
      saveNext(store, bobSessionId, bobState);

      // =====================================================================
      // Step 9: Simulate app restart - reload states from disk
      // =====================================================================
      const aliceReloaded = store.load(aliceSessionId)!;
      const bobReloaded = store.load(bobSessionId)!;

      // Verify states were persisted and reloaded correctly
      expect(aliceReloaded).toBeDefined();
      expect(bobReloaded).toBeDefined();
      expect(aliceReloaded.version).toBe(1);
      expect(bobReloaded.version).toBe(1);
      expect(aliceReloaded.state.version).toBe(1);
      expect(bobReloaded.state.version).toBe(1);

      // =====================================================================
      // Step 10: Out-of-Order Messages (Alice sends 3, Bob receives 3→1→2)
      // =====================================================================
      // Alice encrypts three messages in sequence
      const msg1 = ratchetEncrypt({
        state: aliceReloaded.state,
        plaintext: encode("msg-1"),
        sender_device_id: alice.recipient_device_id,
        recipient_device_id: bob.recipient_device_id,
      });
      saveNext(store, aliceSessionId, aliceReloaded.state);

      const msg2 = ratchetEncrypt({
        state: aliceReloaded.state,
        plaintext: encode("msg-2"),
        sender_device_id: alice.recipient_device_id,
        recipient_device_id: bob.recipient_device_id,
      });
      saveNext(store, aliceSessionId, aliceReloaded.state);

      const msg3 = ratchetEncrypt({
        state: aliceReloaded.state,
        plaintext: encode("msg-3"),
        sender_device_id: alice.recipient_device_id,
        recipient_device_id: bob.recipient_device_id,
      });
      saveNext(store, aliceSessionId, aliceReloaded.state);

      // Verify message numbers increment
      expect(msg1.header.dr.n).toBe(1); // Second message in chain
      expect(msg2.header.dr.n).toBe(2); // Third message in chain
      expect(msg3.header.dr.n).toBe(3); // Fourth message in chain

      // Bob receives messages out of order: 3 → 1 → 2
      // Message 3 arrives first
      const dec3 = ratchetDecrypt({
        state: bobReloaded.state,
        header: msg3.header,
        ciphertext_b64: msg3.ciphertext_b64,
      });
      expect(new TextDecoder().decode(dec3.plaintext)).toBe("msg-3");
      saveNext(store, bobSessionId, bobReloaded.state);

      // Message 1 arrives from skipped cache
      const dec1 = ratchetDecrypt({
        state: bobReloaded.state,
        header: msg1.header,
        ciphertext_b64: msg1.ciphertext_b64,
      });
      expect(new TextDecoder().decode(dec1.plaintext)).toBe("msg-1");
      saveNext(store, bobSessionId, bobReloaded.state);

      // Message 2 arrives from skipped cache
      const dec2 = ratchetDecrypt({
        state: bobReloaded.state,
        header: msg2.header,
        ciphertext_b64: msg2.ciphertext_b64,
      });
      expect(new TextDecoder().decode(dec2.plaintext)).toBe("msg-2");
      saveNext(store, bobSessionId, bobReloaded.state);

      // =====================================================================
      // Step 11: Replay Prevention (Bob rejects duplicate message)
      // =====================================================================
      // Attempting to decrypt msg2 again should fail because the message key
      // was already consumed and deleted from the skipped message cache
      expect(() => {
        ratchetDecrypt({
          state: bobReloaded.state,
          header: msg2.header,
          ciphertext_b64: msg2.ciphertext_b64,
        });
      }).toThrow(); // Should fail - key already consumed

      // Also verify replaying msg1 and msg3 fails
      expect(() => {
        ratchetDecrypt({
          state: bobReloaded.state,
          header: msg1.header,
          ciphertext_b64: msg1.ciphertext_b64,
        });
      }).toThrow();

      expect(() => {
        ratchetDecrypt({
          state: bobReloaded.state,
          header: msg3.header,
          ciphertext_b64: msg3.ciphertext_b64,
        });
      }).toThrow();

      // =====================================================================
      // Verification: Session remains functional after all operations
      // =====================================================================
      // Alice can still send new messages
      const followUp = ratchetEncrypt({
        state: aliceReloaded.state,
        plaintext: encode("follow-up"),
        sender_device_id: alice.recipient_device_id,
        recipient_device_id: bob.recipient_device_id,
      });
      saveNext(store, aliceSessionId, aliceReloaded.state);

      // Bob can decrypt new messages
      const followUpDec = ratchetDecrypt({
        state: bobReloaded.state,
        header: followUp.header,
        ciphertext_b64: followUp.ciphertext_b64,
      });
      expect(new TextDecoder().decode(followUpDec.plaintext)).toBe("follow-up");
      saveNext(store, bobSessionId, bobReloaded.state);

      // =====================================================================
      // Test Complete - All 9 Steps Demonstrated Successfully
      // =====================================================================
    } finally {
      // Clean up temp directory
      rmSync(storeDir, { recursive: true, force: true });
    }
  });
});

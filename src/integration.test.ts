/**
 * End-to-end: one-time prekeys, X3DH v2 with the host's commit order, the Double
 * Ratchet, persistence through FileRatchetStore, out-of-order delivery, replays and
 * a replayed setup after its one-time prekey was deleted.
 */

import { describe, it, expect } from "vitest";
import { mkdtempSync, rmSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { randomBytes } from "@noble/ciphers/utils.js";
import { X3DHPrekeyManagerV2 } from "./x3dh/prekey-manager.js";
import { x3dhInitiatorBootstrapV2, x3dhResponderBootstrapV2 } from "./x3dh/session.js";
import { ratchetEncrypt, ratchetDecrypt } from "./ratchet/ratchet.js";
import { FileRatchetStore } from "./ratchet/file-store.js";
import {
  createPersistedSession,
  ratchetDecryptWithStore,
  ratchetEncryptWithStore,
} from "./ratchet/session-store.js";
import { IdentityRegistry } from "./identity/trust.js";
import { bytesToBase64 } from "./encoding/base64.js";
import { deriveDirectionScopedSessionIdV1 } from "./session-id.js";
import { ReplayDetectedError, UnknownPrekeyError } from "./errors.js";
import { ALICE_DEVICE, BOB_DEVICE } from "./test-fixtures.js";

const encode = (s: string) => new TextEncoder().encode(s);
const decode = (b: Uint8Array) => new TextDecoder().decode(b);

describe("End-to-End Integration", () => {
  it("complete flow: one-time prekey → X3DH → first decrypt → commit → persist → reload → out-of-order → replay", async () => {
    const storeDir = mkdtempSync(join(tmpdir(), "integration-"));
    try {
      // Both devices have keys; Bob mints one-time prekeys for the server to hand out.
      const alice = X3DHPrekeyManagerV2.create({ recipient_device_id: ALICE_DEVICE });
      const bob = X3DHPrekeyManagerV2.create({ recipient_device_id: BOB_DEVICE });
      const minted = bob.mintOneTimePrekeys(10);
      const signedBatch = bob.signOneTimePrekeyBatch(minted.map((k) => k.opk_id));
      expect(signedBatch.prekeys).toHaveLength(10);

      // The server serves Bob's signed bundle with one allocated one-time prekey.
      const served = minted[3]!;
      const bundle = { ...bob.getPrekeyBundle(), opk_id: served.opk_id, opk_pub_b64: bytesToBase64(served.pub32) };

      const aliceTrust = new IdentityRegistry();
      const init = x3dhInitiatorBootstrapV2({
        sender_device_id: ALICE_DEVICE,
        recipient_bundle: bundle,
        expected_recipient_device_id: BOB_DEVICE,
        initiator_ik_priv32: alice.ik.priv32,
        initiator_ik_sig_pub32: alice.ik_sig.pub32,
        trust: aliceTrust,
      });
      expect(init.session_init).toMatchObject({ v: 2, used_opk: true, opk_id: served.opk_id });
      expect(aliceTrust.get(BOB_DEVICE)).not.toBeNull();

      const first = ratchetEncrypt({ state: init.ratchet_state, plaintext: encode("hello") });

      // Bob: bootstrap in memory from the row's sender, trial-decrypt, then commit.
      const bobTrust = new IdentityRegistry();
      const resp = x3dhResponderBootstrapV2({
        session_init: init.session_init,
        prekeys: bob,
        recipient_device_id: BOB_DEVICE,
        sender_device_id: ALICE_DEVICE,
      });
      expect(decode(ratchetDecrypt({ state: resp.ratchet_state, header: first.header, ciphertext_b64: first.ciphertext_b64 }).plaintext)).toBe("hello");
      const peerIdentity = {
        device_id: ALICE_DEVICE,
        ik_pub_b64: init.session_init.sender_ik_pub_b64,
        ik_sig_pub_b64: init.session_init.sender_ik_sig_pub_b64,
      };
      expect(bobTrust.check(peerIdentity)).toBe("unknown");
      bobTrust.assertOrPin(peerIdentity);

      const store = new FileRatchetStore(storeDir, randomBytes(32));
      const aliceId = deriveDirectionScopedSessionIdV1({ my_device_id: ALICE_DEVICE, their_device_id: BOB_DEVICE, direction: "send" });
      const bobId = deriveDirectionScopedSessionIdV1({ my_device_id: BOB_DEVICE, their_device_id: ALICE_DEVICE, direction: "recv" });
      store.save(aliceId, createPersistedSession(init.ratchet_state));
      store.save(bobId, createPersistedSession(resp.ratchet_state));
      expect(bob.removeOneTimePrekey(resp.used.opk_id!)).toBe(true);

      // The same setup again after the one-time prekey was deleted is refused.
      expect(() =>
        x3dhResponderBootstrapV2({
          session_init: init.session_init,
          prekeys: bob,
          recipient_device_id: BOB_DEVICE,
          sender_device_id: ALICE_DEVICE,
        })
      ).toThrow(UnknownPrekeyError);

      // Reload, then three messages delivered 3, 1, 2.
      const msgs = [];
      for (const t of ["msg-1", "msg-2", "msg-3"]) {
        msgs.push(await ratchetEncryptWithStore(store, aliceId, { plaintext: encode(t) }));
      }
      expect(msgs.map((m) => m.header.dr.n)).toEqual([1, 2, 3]);
      for (const i of [2, 0, 1]) {
        expect(decode((await ratchetDecryptWithStore(store, bobId, msgs[i]!)).plaintext)).toBe(`msg-${i + 1}`);
      }
      for (const m of msgs) {
        await expect(ratchetDecryptWithStore(store, bobId, m)).rejects.toBeInstanceOf(ReplayDetectedError);
      }

      // Bob replies; Alice reads it and steps her DH ratchet.
      const reply = await ratchetEncryptWithStore(store, bobId, { plaintext: encode("hi alice") });
      expect(reply.header.sender_device_id).toBe(BOB_DEVICE);
      expect(decode((await ratchetDecryptWithStore(store, aliceId, reply)).plaintext)).toBe("hi alice");
      const next = await ratchetEncryptWithStore(store, aliceId, { plaintext: encode("follow-up") });
      expect(next.header.dr.dh_pub_b64).not.toBe(first.header.dr.dh_pub_b64);
      expect(decode((await ratchetDecryptWithStore(store, bobId, next)).plaintext)).toBe("follow-up");
      expect(store.load(bobId)!.version).toBeGreaterThan(0);
    } finally {
      rmSync(storeDir, { recursive: true, force: true });
    }
  });
});

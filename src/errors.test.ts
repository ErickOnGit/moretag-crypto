import { describe, it, expect } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "@noble/ciphers/utils.js";
import {
  DecryptFailedError,
  IdentityMismatchError,
  RatchetStoreConflictError,
  ReplayDetectedError,
  SessionNotFoundError,
} from "./errors.js";
import { X3DHPrekeyManagerV1 } from "./x3dh/prekey-manager.js";
import { x3dhResponderWithPrekeysV1 } from "./x3dh/session.js";
import { x3dhInitiatorV1 } from "./crypto/x3dh.js";
import { generateX25519Keypair } from "./crypto/x25519.js";
import {
  InMemoryRatchetStore,
  ratchetDecryptWithStore,
  ratchetEncryptWithStore,
  type RatchetSessionStore,
} from "./ratchet/session-store.js";
import { FileRatchetStore } from "./ratchet/file-store.js";
import {
  deserializePersistedSessionV1,
  deserializeRatchetStateV1,
  type SerializedPersistedSessionV1,
  type SerializedRatchetStateV1,
} from "./ratchet/serialization.js";
import { IdentityRegistry } from "./identity/trust.js";
import { bytesToBase64 } from "./encoding/base64.js";

/** Caller-supplied identifiers that must never reach an error message. */
const SENTINEL = "sentinel-3c9e1f";
const SENTINEL_NUM = 918273645;

function thrownBy(fn: () => unknown): Error {
  try {
    fn();
  } catch (err) {
    return err as Error;
  }
  throw new Error("expected a throw");
}

async function rejectedBy(fn: () => Promise<unknown>): Promise<Error> {
  try {
    await fn();
  } catch (err) {
    return err as Error;
  }
  throw new Error("expected a rejection");
}

function expectNoSentinel(err: Error): void {
  expect(err.message).not.toContain(SENTINEL);
  expect(err.message).not.toContain(String(SENTINEL_NUM));
}

describe("typed errors", () => {
  it.each([
    [new ReplayDetectedError(), "ReplayDetectedError", "replay_detected"],
    [new SessionNotFoundError(), "SessionNotFoundError", "session_not_found"],
    [new RatchetStoreConflictError(), "RatchetStoreConflictError", "store_conflict"],
    [
      new IdentityMismatchError({
        deviceId: SENTINEL,
        pinnedIkPubB64: "a",
        observedIkPubB64: "b",
        pinnedIkSigPubB64: "c",
        observedIkSigPubB64: "d",
      }),
      "IdentityMismatchError",
      "identity_mismatch",
    ],
    [new DecryptFailedError(), "DecryptFailedError", "decrypt_failed"],
  ] as const)("%o has its name and code", (err, name, code) => {
    expect(err).toBeInstanceOf(Error);
    expect(err.name).toBe(name);
    expect(err.code).toBe(code);
    expectNoSentinel(err);
  });
});

describe("no library message names a caller-supplied identifier", () => {
  it("recipient device mismatch at the responder", () => {
    const bob = new X3DHPrekeyManagerV1({ recipient_device_id: SENTINEL });
    bob.rotateSignedPrekey(1);
    const { session_init } = x3dhInitiatorV1({
      sender_device_id: "alice-device",
      recipient_bundle: bob.getPrekeyBundle(),
      initiator_ik_priv32: generateX25519Keypair().priv32,
    });
    const other = new X3DHPrekeyManagerV1({ recipient_device_id: `${SENTINEL_NUM}` });
    other.rotateSignedPrekey(1);

    expectNoSentinel(thrownBy(() => x3dhResponderWithPrekeysV1({ session_init, prekeys: other })));
  });

  it("unknown signed or one-time prekey ids, as strings and numbers", () => {
    const bob = X3DHPrekeyManagerV1.create({ recipient_device_id: "bob-device", initial_opk_count: 1 });
    for (const id of [SENTINEL, SENTINEL_NUM]) {
      expectNoSentinel(thrownBy(() => bob.getSignedPrekeyPriv32(id)));
      expectNoSentinel(thrownBy(() => bob.getOneTimePrekeyPriv32(id)));
      expectNoSentinel(thrownBy(() => bob.consumeOneTimePrekey(id)));
    }
  });

  it("missing session on every store path", async () => {
    const fn = () => {
      throw new Error("never called");
    };
    expectNoSentinel(thrownBy(() => new InMemoryRatchetStore().transact(SENTINEL, fn)));

    const loadSaveOnly: RatchetSessionStore = { load: () => undefined, save: () => {} };
    const encryptArgs = {
      plaintext: new Uint8Array(1),
      sender_device_id: "a",
      recipient_device_id: "b",
    };
    expectNoSentinel(
      await rejectedBy(() =>
        ratchetEncryptWithStore(loadSaveOnly, SENTINEL, encryptArgs as never)
      )
    );
    expectNoSentinel(
      await rejectedBy(() =>
        ratchetDecryptWithStore(loadSaveOnly, SENTINEL, {} as never)
      )
    );

    const dir = mkdtempSync(join(tmpdir(), "errors-"));
    try {
      const store = new FileRatchetStore(dir, randomBytes(32));
      expectNoSentinel(thrownBy(() => store.transact(SENTINEL, fn)));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("unsupported serialized versions", () => {
    const state = { v: SENTINEL } as unknown as SerializedRatchetStateV1;
    expectNoSentinel(thrownBy(() => deserializeRatchetStateV1(state)));
    const record = { v: SENTINEL_NUM } as unknown as SerializedPersistedSessionV1;
    expectNoSentinel(thrownBy(() => deserializePersistedSessionV1(record)));
  });

  it("identity mismatch", () => {
    const key = (fill: number) => bytesToBase64(new Uint8Array(32).fill(fill));
    const reg = new IdentityRegistry();
    reg.assertOrPin({ device_id: SENTINEL, ik_pub_b64: key(1), ik_sig_pub_b64: key(2) });
    const err = thrownBy(() =>
      reg.assertOrPin({ device_id: SENTINEL, ik_pub_b64: key(3), ik_sig_pub_b64: key(2) })
    );
    expect(err).toBeInstanceOf(IdentityMismatchError);
    expectNoSentinel(err);
  });
});

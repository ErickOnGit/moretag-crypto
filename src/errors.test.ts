import { describe, it, expect } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "@noble/ciphers/utils.js";
import {
  BadSignatureError,
  DecryptFailedError,
  DeviceMismatchError,
  IdentityMismatchError,
  InvalidDeviceIdError,
  InvalidWireError,
  LowOrderKeyError,
  NoSendingChainError,
  RatchetStoreConflictError,
  ReplayDetectedError,
  SelfSessionError,
  SessionNotFoundError,
  UnknownPrekeyError,
} from "./errors.js";
import { X3DHPrekeyManagerV2 } from "./x3dh/prekey-manager.js";
import { x3dhResponderBootstrapV2 } from "./x3dh/session.js";
import { decodeHeaderV2 } from "./wire/header.js";
import { assertCanonicalDeviceId } from "./crypto/device-id.js";
import { ALICE_DEVICE, BOB_DEVICE, sessionPair } from "./test-fixtures.js";
import {
  InMemoryRatchetStore,
  ratchetDecryptWithStore,
  ratchetEncryptWithStore,
  type RatchetSessionStore,
} from "./ratchet/session-store.js";
import { FileRatchetStore } from "./ratchet/file-store.js";
import {
  deserializePersistedSessionV2,
  deserializeRatchetStateV2,
  type SerializedPersistedSessionV2,
  type SerializedRatchetStateV2,
} from "./ratchet/serialization.js";
import { IdentityRegistry } from "./identity/trust.js";
import { bytesToBase64 } from "./encoding/base64.js";

/** Caller-supplied identifiers that must never reach an error message. */
const SENTINEL = "5e471e1a-3c9e-4f1d-9b2a-7c6d5e4f3a21";
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
    [new UnknownPrekeyError("unknown_spk"), "UnknownPrekeyError", "unknown_spk"],
    [new UnknownPrekeyError("unknown_opk"), "UnknownPrekeyError", "unknown_opk"],
    [new DeviceMismatchError(), "DeviceMismatchError", "device_mismatch"],
    [new SelfSessionError(), "SelfSessionError", "self_session"],
    [new NoSendingChainError(), "NoSendingChainError", "no_sending_chain"],
    [new InvalidDeviceIdError(), "InvalidDeviceIdError", "invalid_device_id"],
    [new InvalidWireError("invalid_header", "dr.n"), "InvalidWireError", "invalid_header"],
    [new InvalidWireError("invalid_grp", "grp"), "InvalidWireError", "invalid_grp"],
    [new InvalidWireError("invalid_session_init", "v"), "InvalidWireError", "invalid_session_init"],
    [new InvalidWireError("invalid_bundle", "v"), "InvalidWireError", "invalid_bundle"],
    [new BadSignatureError(), "BadSignatureError", "bad_signature"],
    [new LowOrderKeyError(), "LowOrderKeyError", "low_order_key"],
  ] as const)("%o has its name and code", (err, name, code) => {
    expect(err).toBeInstanceOf(Error);
    expect(err.name).toBe(name);
    expect(err.code).toBe(code);
    expectNoSentinel(err);
  });
});

describe("no library message names a caller-supplied identifier", () => {
  it("device mismatches at the responder", () => {
    const { session_init, bobKeys } = sessionPair({ opkId: SENTINEL_NUM });
    // The row names another sender than the sidecar.
    expectNoSentinel(
      thrownBy(() =>
        x3dhResponderBootstrapV2({ session_init, prekeys: bobKeys, recipient_device_id: BOB_DEVICE, sender_device_id: SENTINEL })
      )
    );
    // A sidecar for another recipient.
    expectNoSentinel(
      thrownBy(() =>
        x3dhResponderBootstrapV2({
          session_init: { ...session_init, recipient_device_id: SENTINEL },
          prekeys: bobKeys,
          recipient_device_id: BOB_DEVICE,
          sender_device_id: ALICE_DEVICE,
        })
      )
    );
  });

  it("unknown signed or one-time prekey ids", () => {
    const bob = X3DHPrekeyManagerV2.create({ recipient_device_id: BOB_DEVICE, initial_opk_count: 1 });
    expectNoSentinel(thrownBy(() => bob.getSignedPrekeyPriv32(SENTINEL_NUM)));
    expectNoSentinel(thrownBy(() => bob.getOneTimePrekeyPriv32(SENTINEL_NUM)));
    expectNoSentinel(thrownBy(() => bob.signOneTimePrekeyBatch([SENTINEL_NUM])));
  });

  it("malformed wire objects and device ids name the field, never the value", () => {
    const bad = `${SENTINEL}X`;
    expectNoSentinel(thrownBy(() => assertCanonicalDeviceId(bad)));
    expectNoSentinel(
      thrownBy(() =>
        decodeHeaderV2({
          v: 2,
          alg: "xchacha20poly1305",
          nonce_b64: SENTINEL,
          sender_device_id: ALICE_DEVICE,
          recipient_device_id: BOB_DEVICE,
          dr: { dh_pub_b64: "", pn: 0, n: 0 },
        })
      )
    );
    expectNoSentinel(thrownBy(() => decodeHeaderV2({ v: 2, alg: "xchacha20poly1305", nonce_b64: "", sender_device_id: bad })));
    expectNoSentinel(thrownBy(() => X3DHPrekeyManagerV2.fromState({ v: 2, recipient_device_id: bad } as never)));
  });

  it("missing session on every store path", async () => {
    const fn = () => {
      throw new Error("never called");
    };
    expectNoSentinel(thrownBy(() => new InMemoryRatchetStore().transact(SENTINEL, fn)));

    const loadSaveOnly: RatchetSessionStore = { load: () => undefined, save: () => {} };
    const encryptArgs = { plaintext: new Uint8Array(1) };
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
    const state = { v: SENTINEL } as unknown as SerializedRatchetStateV2;
    expectNoSentinel(thrownBy(() => deserializeRatchetStateV2(state)));
    const record = { v: SENTINEL_NUM } as unknown as SerializedPersistedSessionV2;
    expectNoSentinel(thrownBy(() => deserializePersistedSessionV2(record)));
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

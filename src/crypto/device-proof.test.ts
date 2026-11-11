/**
 * The prekey manager signs a device proof only as its own device. The bytes, the
 * verifier's order and the build refusals are pinned by src/vectors/device-proof.test.ts.
 */
import { test, expect } from "vitest";
import { buildDeviceProofMessage, verifyDeviceProof, type DeviceProofFields } from "./device-proof.js";
import { ed25519Sign, generateEd25519Keypair } from "./ed25519.js";
import { base64ToBytes } from "../encoding/base64.js";
import { X3DHPrekeyManagerV2 } from "../x3dh/prekey-manager.js";
import { ALICE_DEVICE, BOB_DEVICE } from "../test-fixtures.js";

test("signDeviceProof signs as the manager's own device, whatever a caller passes", () => {
  const bob = X3DHPrekeyManagerV2.create({ recipient_device_id: BOB_DEVICE });
  const alice = X3DHPrekeyManagerV2.create({ recipient_device_id: ALICE_DEVICE });
  const fields = {
    action: "remove",
    session_id: "5e551011-0000-4000-8000-000000000001",
    issued_at_s: 1_762_560_000,
    target_device_id: ALICE_DEVICE,
  } as const;
  // A JavaScript caller can pass an acting id the type leaves out; the manager's own wins.
  const proof = bob.signDeviceProof({ ...fields, acting_device_id: ALICE_DEVICE } as Omit<DeviceProofFields, "acting_device_id">);
  const signingKey = (m: X3DHPrekeyManagerV2) => base64ToBytes(m.exportState().ik_ed25519_pub_b64);
  const check = (acting_device_id: string, m: X3DHPrekeyManagerV2) =>
    verifyDeviceProof({
      fields: { ...fields, acting_device_id },
      acting_ik_sig_pub32: signingKey(m),
      proof_sig64: base64ToBytes(proof),
      now_s: fields.issued_at_s,
    });
  expect(check(BOB_DEVICE, bob)).toBe("valid");
  expect(check(ALICE_DEVICE, alice)).toBe("bad_signature");
});

test("a clock that isn't a whole number of seconds throws, never answers valid", () => {
  const { priv32, pub32 } = generateEd25519Keypair();
  const fields: DeviceProofFields = { action: "reset", acting_device_id: BOB_DEVICE, session_id: "5e551011-0000-4000-8000-000000000001", issued_at_s: 100 };
  const proof_sig64 = ed25519Sign(priv32, buildDeviceProofMessage(fields));
  const verify = (now_s: number) => verifyDeviceProof({ fields, acting_ik_sig_pub32: pub32, proof_sig64, now_s });
  expect(verify(100)).toBe("valid");
  for (const now_s of [NaN, Infinity, -Infinity, 100.5, -1]) {
    expect(() => verify(now_s), String(now_s)).toThrow(TypeError);
  }
});

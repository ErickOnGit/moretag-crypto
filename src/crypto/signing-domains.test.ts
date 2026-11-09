/**
 * Every message the identity signing key (Ed25519) signs is a CBOR array that
 * begins with its own domain string, so a signature made for one purpose can never
 * verify for another.
 */
import { test, expect, afterEach } from "vitest";
import { decode } from "cbor-x";
import { getPrimitives, registerCryptoPrimitives, resetCryptoPrimitives } from "./primitives.js";
import { OPK_BATCH_SIGNATURE_DOMAIN, SPK_SIGNATURE_DOMAIN } from "./x3dh.js";
import { DEVICE_PROOF_DOMAIN } from "./device-proof.js";
import { X3DHPrekeyManagerV2 } from "../x3dh/prekey-manager.js";
import { ALICE_DEVICE, BOB_DEVICE } from "../test-fixtures.js";

afterEach(() => resetCryptoPrimitives());

test("each signing path signs a CBOR array that starts with its own domain string", () => {
  const noble = getPrimitives();
  const signed: Uint8Array[] = [];
  let recording = false;
  registerCryptoPrimitives({
    name: "recording-signer",
    randomBytes: noble.randomBytes,
    ed25519Sign: (seed, message) => {
      if (recording) signed.push(message.slice());
      return noble.ed25519Sign(seed, message);
    },
  });

  const bob = X3DHPrekeyManagerV2.create({ recipient_device_id: BOB_DEVICE });
  bob.mintOneTimePrekeys(2);
  recording = true;
  bob.getPrekeyBundle();
  bob.signOneTimePrekeyBatch([1, 2]);
  bob.signDeviceProof({ action: "remove", session_id: "5e551011-0000-4000-8000-000000000001", issued_at_s: 1, target_device_id: ALICE_DEVICE });
  recording = false;

  const domains = signed.map((m) => {
    const value = decode(m) as unknown;
    expect(Array.isArray(value)).toBe(true);
    const [domain, second, third] = value as unknown[];
    // The device proof names its action second and the signing device third.
    expect(domain === DEVICE_PROOF_DOMAIN ? third : second).toBe(BOB_DEVICE);
    return domain;
  });
  expect(domains).toEqual([SPK_SIGNATURE_DOMAIN, OPK_BATCH_SIGNATURE_DOMAIN, DEVICE_PROOF_DOMAIN]);
  expect(SPK_SIGNATURE_DOMAIN).toBe("moretag/x3dh/spk/v1");
  expect(OPK_BATCH_SIGNATURE_DOMAIN).toBe("moretag/x3dh/opk-batch/v1");
  expect(DEVICE_PROOF_DOMAIN).toBe("moretag/device-proof/v1");
  expect(new Set(domains).size).toBe(domains.length);
});

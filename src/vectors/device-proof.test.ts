/**
 * vectors/device-proof-v1.json and vectors/device-code-v1.json, written by
 * scripts/gen-vectors-device-v1.mjs (an author who worked from SPEC §4.5 only and
 * read no library source). Each case runs through the public API on every provider.
 *
 * The files' `fields` use the author's names: `target_ik_sig_pub_hex` for the key,
 * and in a verify case's overrides `null` removes a field.
 */
import { describe, it, expect, afterEach } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { hex, loadVector, unhex, PROVIDERS, resetProviders, scriptedRandomness } from "./support.js";
import {
  DEVICE_CODE_DOMAIN,
  DEVICE_PROOF_DOMAIN,
  InvalidDeviceIdError,
  X3DHPrekeyManagerV2,
  bytesToBase64,
  buildDeviceProofMessage,
  deviceCode,
  verifyDeviceProof,
  type DeviceProofFields,
} from "../index.js";

const PROOF = loadVector("device-proof-v1.json");
const CODE = loadVector("device-code-v1.json");

/** The author's field object as the library's. */
function libraryFields(f: Record<string, any>): DeviceProofFields {
  const { target_ik_sig_pub_hex, ...rest } = f;
  return {
    ...rest,
    ...(typeof target_ik_sig_pub_hex === "string" ? { target_ik_sig_pub32: unhex(target_ik_sig_pub_hex) } : {}),
  } as DeviceProofFields;
}

function withOverrides(base: Record<string, any>, overrides: Record<string, any>): Record<string, any> {
  const out = { ...base };
  for (const [k, v] of Object.entries(overrides)) {
    if (v === null) delete out[k];
    else out[k] = v;
  }
  return out;
}

const caseNamed = (name: string) => {
  const c = PROOF.valid.find((v: any) => v.name === name);
  if (!c) throw new Error(`no valid case ${name}`);
  return c;
};

afterEach(() => resetProviders());

it("the generator imports only node:crypto, node:fs and node:path", () => {
  const source = readFileSync(join(process.cwd(), "scripts", "gen-vectors-device-v1.mjs"), "utf-8");
  const specifiers = [...source.matchAll(/\b(?:import|export)\b[^'"`;]*?\bfrom\s*(['"])([^'"]+)\1|\bimport\s*(['"])([^'"]+)\3/g)]
    .map((m) => m[2] ?? m[4]);
  expect([...new Set(specifiers)].sort()).toEqual(["node:crypto", "node:fs", "node:path"]);
  expect(source).not.toMatch(/\brequire\s*\(|\bimport\s*\(/);
});

it("the files name the library's domains", () => {
  expect(PROOF.domain).toBe(DEVICE_PROOF_DOMAIN);
  expect(CODE.domain).toBe(DEVICE_CODE_DOMAIN);
});

for (const provider of PROVIDERS) {
  describe(`device proof on ${provider.name}`, () => {
    // No draws: signing and verifying are deterministic. Real randomness until a queue is loaded.
    const register = () => scriptedRandomness(provider.name);

    it("every valid case: message bytes, signature, and the manager signs the same", () => {
      register();
      const acting = PROOF.parties.acting;
      const mgr = X3DHPrekeyManagerV2.fromState({
        v: 2,
        recipient_device_id: acting.device_id,
        ik_x25519_priv_b64: bytesToBase64(new Uint8Array(32).fill(7)),
        ik_x25519_pub_b64: bytesToBase64(new Uint8Array(32).fill(8)),
        ik_ed25519_priv_b64: bytesToBase64(unhex(acting.ik_sig_seed_hex)),
        ik_ed25519_pub_b64: bytesToBase64(unhex(acting.ik_sig_public_hex)),
        current_spk_id: null,
        spks: [],
        opks: [],
        next_opk_id: 1,
      });
      expect(PROOF.valid.length).toBeGreaterThanOrEqual(15);
      for (const v of PROOF.valid) {
        const fields = libraryFields(v.fields);
        expect(hex(buildDeviceProofMessage(fields)), v.name).toBe(v.message_cbor_hex);
        if (v.message_parts_hex) {
          expect(v.message_parts_hex.map((p: any) => p.hex).join(""), v.name).toBe(v.message_cbor_hex);
        }
        expect(fields.acting_device_id).toBe(acting.device_id);
        const { acting_device_id: _a, ...rest } = fields;
        expect(hex(Buffer.from(mgr.signDeviceProof(rest), "base64")), v.name).toBe(v.signature_hex);
        expect(
          verifyDeviceProof({ fields, acting_ik_sig_pub32: unhex(acting.ik_sig_public_hex), proof_sig64: unhex(v.signature_hex), now_s: fields.issued_at_s }),
          v.name
        ).toBe("valid");
      }
    });

    it("every verify case gives its verdict", () => {
      register();
      expect(PROOF.verify.length).toBeGreaterThanOrEqual(20);
      for (const c of PROOF.verify) {
        const base = caseNamed(c.base);
        const fields = libraryFields(withOverrides(base.fields, c.verifier.fields));
        const verdict = verifyDeviceProof({
          fields,
          acting_ik_sig_pub32: unhex(c.verifier.signer_ik_sig_public_hex),
          proof_sig64: unhex(c.signature_hex),
          now_s: c.verifier.now_s,
        });
        expect(verdict, c.name).toBe(c.expect);
      }
    });
  });
}

it("every build refusal throws its kind, and the verifier refuses the same fields", () => {
  const key = unhex(PROOF.parties.acting.ik_sig_public_hex);
  for (const r of PROOF.refusals) {
    const fields = libraryFields(r.fields);
    for (const run of [
      () => buildDeviceProofMessage(fields),
      () => verifyDeviceProof({ fields, acting_ik_sig_pub32: key, proof_sig64: new Uint8Array(64), now_s: 0 }),
    ]) {
      let thrown: unknown;
      try {
        run();
      } catch (err) {
        thrown = err;
      }
      expect(thrown, r.name).toBeInstanceOf(TypeError);
      expect(thrown instanceof InvalidDeviceIdError, r.name).toBe(r.expect === "invalid_device_id");
    }
  }
});

it("device-code-v1.json: every code, and the refusals", () => {
  expect(CODE.cases.length).toBeGreaterThanOrEqual(12);
  for (const c of CODE.cases) {
    expect(deviceCode(unhex(c.ik_sig_public_hex)), c.name).toBe(c.code);
    expect(c.code, c.name).toMatch(/^[0-9]{6}$/);
  }
  // The file holds a collision, a leading zero and the modulo's last, partial block.
  const codes = CODE.cases.map((c: any) => c.code);
  expect(new Set(codes).size).toBeLessThan(codes.length);
  expect(codes.some((c: string) => c.startsWith("0"))).toBe(true);
  expect(CODE.cases.some((c: any) => c.uint32 >= 4_294_000_000)).toBe(true);
  for (const r of CODE.refusals) {
    expect(() => deviceCode(unhex(r.ik_sig_public_hex)), r.name).toThrow(TypeError);
  }
});

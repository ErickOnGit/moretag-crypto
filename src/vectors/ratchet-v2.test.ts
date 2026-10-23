/**
 * vectors/ratchet-v2.json through the public API, once per provider: the X3DH
 * setup through the bootstraps, then every step in order with one scripted
 * randomness queue, a save and reload through the public serializers, a message
 * with the group slot filled, and every refusal with its code and the state
 * unchanged.
 */
import { describe, it, expect, afterEach } from "vitest";
import {
  comparable,
  hex,
  hexToB64,
  libraryHeader,
  librarySessionInit,
  libraryState,
  loadVector,
  partyPrekeys,
  PROVIDERS,
  resetProviders,
  scriptedRandomness,
  thrownBy,
  unhex,
  vectorHeader,
} from "./support.js";
import { x3dhInitiatorBootstrapV2, x3dhResponderBootstrapV2 } from "../x3dh/session.js";
import { ratchetDecrypt, ratchetEncrypt, type RatchetState } from "../ratchet/ratchet.js";
import { deserializeRatchetStateV2, serializeRatchetStateV2 } from "../ratchet/serialization.js";
import { buildDeliveryAadV2, encodeHeaderV2 } from "../crypto/aad.js";
import { IdentityRegistry } from "../identity/trust.js";

const file = loadVector("ratchet-v2.json");
const { alice, bob } = file.setup.parties;

/** Codes the library assigns where the design named none (expected_code null). */
const ASSIGNED_PREFIX = "malformed_grp_";
const expectedCode = (r: any): string => {
  if (r.expected_code !== null) return r.expected_code;
  if (r.name.startsWith(ASSIGNED_PREFIX)) return "invalid_grp";
  throw new Error(`no library code assigned for ${r.name}`);
};

afterEach(() => resetProviders());

describe.each(PROVIDERS.map((p) => p.name))("ratchet-v2.json on %s", (providerName) => {
  it("runs the whole script byte for byte, with every draw in order", () => {
    const rng = scriptedRandomness(providerName);
    rng.load([...file.setup.x3dh_draws, ...file.draws]);

    const bobKeys = partyPrekeys(bob, { opk_ids: [] });
    const states: Record<string, RatchetState | undefined> = {};
    const messages = new Map<string, any>(file.messages.map((m: any) => [m.id, m]));

    for (const step of file.steps) {
      switch (step.op) {
        case "ratchet_init_initiator": {
          const init = x3dhInitiatorBootstrapV2({
            sender_device_id: alice.device_id,
            recipient_bundle: bobKeys.getPrekeyBundle(),
            expected_recipient_device_id: bob.device_id,
            initiator_ik_priv32: unhex(alice.ik.private_hex),
            initiator_ik_sig_pub32: unhex(alice.ik_sig.public_hex),
            trust: new IdentityRegistry(),
          });
          expect(init.session_init).toEqual(librarySessionInit(file.setup.session_init));
          states.alice = init.ratchet_state;
          expect(hex(init.ratchet_state.ad)).toBe(file.setup.ad_hex);
          break;
        }
        case "ratchet_init_responder": {
          const resp = x3dhResponderBootstrapV2({
            session_init: librarySessionInit(file.setup.session_init),
            prekeys: bobKeys,
            recipient_device_id: bob.device_id,
            sender_device_id: alice.device_id,
          });
          expect(resp.used).toEqual({ spk_id: bob.spk.id });
          expect(hex(resp.ratchet_state.rk32)).toBe(file.setup.sk_hex);
          states.bob = resp.ratchet_state;
          break;
        }
        case "encrypt": {
          const m = messages.get(step.message);
          const grp = m.header.grp;
          const out = ratchetEncrypt({ state: states[step.actor]!, plaintext: unhex(m.plaintext_hex), ...(grp ? { grp } : {}) });
          expect(vectorHeader(out.header), step.message).toEqual(m.header);
          expect(hex(encodeHeaderV2(out.header))).toBe(m.h_cbor_hex);
          expect(hex(buildDeliveryAadV2(states[step.actor]!.ad, out.header))).toBe(m.aad_hex);
          expect(out.ciphertext_b64, step.message).toBe(hexToB64(m.ciphertext_hex));
          break;
        }
        case "decrypt": {
          const m = messages.get(step.message);
          const out = ratchetDecrypt({
            state: states[step.actor]!,
            header: libraryHeader(m.header),
            ciphertext_b64: hexToB64(m.ciphertext_hex),
          });
          expect(hex(out.plaintext), step.message).toBe(step.expect_plaintext_hex);
          expect(out.grp).toEqual(m.header.grp ?? null);
          break;
        }
        case "save_and_reload": {
          const text = JSON.stringify(serializeRatchetStateV2(states[step.actor]!));
          states[step.actor] = deserializeRatchetStateV2(JSON.parse(text));
          expect(JSON.stringify(serializeRatchetStateV2(states[step.actor]!))).toBe(text);
          expect(comparable(JSON.parse(text))).toEqual(comparable(libraryState(step.serialized)));
          break;
        }
        default:
          throw new Error(`unknown step ${step.op}`);
      }
      if (step.state_after) {
        expect(comparable(serializeRatchetStateV2(states[step.actor]!)), `step ${step.step}`).toEqual(
          comparable(libraryState(step.state_after))
        );
      }
    }
    expect(rng.remaining()).toBe(0);
  });

  for (const r of file.refusals) {
    it(`${r.name} is refused with ${expectedCode(r)} and leaves the state unchanged`, () => {
      scriptedRandomness(providerName); // ordinary randomness
      const state = deserializeRatchetStateV2(libraryState(r.state_before));
      const before = JSON.stringify(serializeRatchetStateV2(state));
      const err = r.deliver
        ? thrownBy(() =>
            ratchetDecrypt({
              state,
              header: libraryHeader(r.deliver.header),
              ciphertext_b64: hexToB64(r.deliver.ciphertext_hex),
            })
          )
        : thrownBy(() => ratchetEncrypt({ state, plaintext: unhex(r.encrypt_plaintext_hex) }));
      expect(err.code).toBe(expectedCode(r));
      expect(JSON.stringify(serializeRatchetStateV2(state))).toBe(before);
      expect(r.state_unchanged).toBe(true);
    });
  }
});

/**
 * vectors/x3dh-v2.json through the public API, once per provider, with the
 * vectors' draws fed to a scripted-randomness provider in order.
 */
import { describe, it, expect, afterEach } from "vitest";
import {
  comparable,
  hex,
  hexToB64,
  libraryBundle,
  libraryHeader,
  librarySessionInit,
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
import { buildSpkSigMessage, x3dhResponderV2 } from "../crypto/x3dh.js";
import { buildAssociatedDataV2 } from "../crypto/ad.js";
import { buildDeliveryAadV2, encodeHeaderV2 } from "../crypto/aad.js";
import { x25519PublicFromPrivate, x25519SharedSecret } from "../crypto/x25519.js";
import { hkdfSha256 } from "../crypto/hkdf.js";
import { kdfChainKey } from "../crypto/kdf.js";
import { ratchetDecrypt, ratchetEncrypt, ratchetInitResponderV2 } from "../ratchet/ratchet.js";
import { serializeRatchetStateV2 } from "../ratchet/serialization.js";
import { IdentityRegistry } from "../identity/trust.js";

const file = loadVector("x3dh-v2.json");

/**
 * Codes the library assigns where the design named none (the vector's
 * expected_code is null: "refused with any typed error").
 */
const ASSIGNED: Record<string, string> = {
  low_order_ek_zero: "low_order_key",
  low_order_ek_one: "low_order_key",
  low_order_ek_order_8_a: "low_order_key",
  low_order_ek_order_8_b: "low_order_key",
  low_order_ek_p_minus_1: "low_order_key",
  low_order_ek_p: "low_order_key",
  low_order_ek_p_plus_1: "low_order_key",
  opk_id_without_used_opk: "invalid_session_init",
  missing_sender_ik_sig_pub: "invalid_session_init",
  bundle_bad_signature: "bad_signature",
};

function expectedCode(r: { name: string; expected_code: string | null }): string {
  if (r.expected_code !== null) return r.expected_code;
  const code = ASSIGNED[r.name];
  if (!code) throw new Error(`no library code assigned for ${r.name}`);
  return code;
}

afterEach(() => resetProviders());

describe.each(PROVIDERS.map((p) => p.name))("x3dh-v2.json on %s", (providerName) => {
  for (const sc of file.scenarios) {
    const alice = sc.parties.alice;
    const bob = sc.parties.bob;

    it(`${sc.name}: every byte, in the draw order`, () => {
      const rng = scriptedRandomness(providerName);

      // The signed-prekey message and signature, and Bob's own bundle.
      const bobKeys = partyPrekeys(bob);
      const sigMsg = buildSpkSigMessage({
        recipient_device_id: bob.device_id,
        ik_pub32: unhex(bob.ik.public_hex),
        spk_pub32: unhex(bob.spk.public_hex),
        spk_id: bob.spk.id,
      });
      expect(hex(sigMsg)).toBe(sc.bundle.spk_signature_message_cbor_hex);
      const ownBundle = bobKeys.getPrekeyBundle();
      expect(ownBundle.spk_sig_b64).toBe(hexToB64(sc.bundle.spk_signature_hex));
      const { opk_id: _id, opk_pub_b64: _pub, ...spkOnly } = sc.bundle.wire;
      expect(ownBundle).toEqual(libraryBundle(spkOnly));

      // DH1..DH4, KM, SK (with and without F), AD, from the published keys.
      const ek = unhex(sc.x3dh.ek_private_hex);
      expect(hex(x25519PublicFromPrivate(ek))).toBe(sc.x3dh.ek_public_hex);
      const dhs = [
        x25519SharedSecret(unhex(alice.ik.private_hex), unhex(bob.spk.public_hex)),
        x25519SharedSecret(ek, unhex(bob.ik.public_hex)),
        x25519SharedSecret(ek, unhex(bob.spk.public_hex)),
        ...(sc.one_time_prekey_used ? [x25519SharedSecret(ek, unhex(bob.opk.public_hex))] : []),
      ];
      dhs.forEach((d, i) => expect(hex(d)).toBe(sc.x3dh[`dh${i + 1}_hex`]));
      expect(sc.x3dh.km_hex).toBe("ff".repeat(32) + dhs.map(hex).join(""));
      const info = new TextEncoder().encode("moretag/x3dh/v2");
      expect(hex(hkdfSha256(unhex(sc.x3dh.km_hex), new Uint8Array(32), info, 32))).toBe(sc.x3dh.sk_hex);
      expect(sc.x3dh.sk_without_f_hex).not.toBe(sc.x3dh.sk_hex);
      const ad = buildAssociatedDataV2({
        initiator_ik_pub32: unhex(alice.ik.public_hex),
        responder_ik_pub32: unhex(bob.ik.public_hex),
        initiator_ik_sig_pub32: unhex(alice.ik_sig.public_hex),
        responder_ik_sig_pub32: unhex(bob.ik_sig.public_hex),
        initiator_device_id: alice.device_id,
        responder_device_id: bob.device_id,
      });
      expect(hex(ad)).toBe(sc.ad.hex);

      // The responder's low-level X3DH gives the same SK and AD.
      const low = x3dhResponderV2({
        session_init: librarySessionInit(sc.session_init),
        sender_device_id: alice.device_id,
        recipient_device_id: bob.device_id,
        recipient_ik_priv32: unhex(bob.ik.private_hex),
        recipient_ik_sig_pub32: unhex(bob.ik_sig.public_hex),
        recipient_spk_priv32: unhex(bob.spk.private_hex),
        ...(sc.one_time_prekey_used ? { recipient_opk_priv32: unhex(bob.opk.private_hex) } : {}),
      });
      expect(hex(low.sk32)).toBe(sc.x3dh.sk_hex);
      expect(hex(low.ad)).toBe(sc.ad.hex);

      // The scripted run: EK, DHs, nonce for Alice; one DHs for Bob's first decrypt.
      rng.load(sc.draws);
      const trust = new IdentityRegistry();
      const init = x3dhInitiatorBootstrapV2({
        sender_device_id: alice.device_id,
        recipient_bundle: libraryBundle(sc.bundle.wire),
        expected_recipient_device_id: sc.expected_recipient_device_id,
        initiator_ik_priv32: unhex(alice.ik.private_hex),
        initiator_ik_sig_pub32: unhex(alice.ik_sig.public_hex),
        trust,
      });
      expect(init.session_init).toEqual(librarySessionInit(sc.session_init));
      expect(trust.check({ device_id: bob.device_id, ik_pub_b64: hexToB64(bob.ik.public_hex), ik_sig_pub_b64: hexToB64(bob.ik_sig.public_hex) })).toBe("match");
      const initState = serializeRatchetStateV2(init.ratchet_state);
      expect(comparable(initState)).toEqual(comparable(sc.initiator_ratchet_init.state));
      expect(initState.rk32_b64).toBe(hexToB64(sc.initiator_ratchet_init.rk_hex));
      expect(initState.ck_s32_b64).toBe(hexToB64(sc.initiator_ratchet_init.ck_s_hex));
      expect(hex(kdfChainKey(unhex(sc.initiator_ratchet_init.ck_s_hex)).mk32)).toBe(sc.first_message.message_key_hex);

      const fm = sc.first_message;
      const enc = ratchetEncrypt({ state: init.ratchet_state, plaintext: unhex(fm.plaintext_hex) });
      expect(vectorHeader(enc.header)).toEqual(fm.header);
      expect(hex(encodeHeaderV2(enc.header))).toBe(fm.h_cbor_hex);
      expect(hex(buildDeliveryAadV2(init.ratchet_state.ad, enc.header))).toBe(fm.aad_hex);
      expect(enc.ciphertext_b64).toBe(hexToB64(fm.ciphertext_hex));
      expect(comparable(serializeRatchetStateV2(enc.state))).toEqual(comparable(sc.initiator_state_after_first_encrypt));

      const resp = x3dhResponderBootstrapV2({
        session_init: librarySessionInit(sc.session_init),
        prekeys: bobKeys,
        recipient_device_id: bob.device_id,
        sender_device_id: alice.device_id,
      });
      expect(resp.used).toEqual(sc.responder_used);
      expect(comparable(serializeRatchetStateV2(resp.ratchet_state))).toEqual(comparable(sc.responder_ratchet_init.state));
      const dec = ratchetDecrypt({
        state: resp.ratchet_state,
        header: libraryHeader(fm.header),
        ciphertext_b64: hexToB64(fm.ciphertext_hex),
      });
      expect(hex(dec.plaintext)).toBe(fm.plaintext_hex);
      expect(dec.grp).toBeNull();
      expect(comparable(serializeRatchetStateV2(dec.state))).toEqual(comparable(sc.responder_state_after_first_decrypt));
      expect(rng.remaining()).toBe(0);
    });

    for (const r of sc.refusals) {
      it(`${sc.name}: ${r.name} is refused with ${expectedCode(r)} and changes nothing`, () => {
        scriptedRandomness(providerName); // ordinary randomness
        const want = expectedCode(r);

        if (r.bundle) {
          const trust = new IdentityRegistry();
          const err = thrownBy(() =>
            x3dhInitiatorBootstrapV2({
              sender_device_id: alice.device_id,
              recipient_bundle: libraryBundle(r.bundle),
              expected_recipient_device_id: r.expected_recipient_device_id,
              initiator_ik_priv32: unhex(alice.ik.private_hex),
              initiator_ik_sig_pub32: unhex(alice.ik_sig.public_hex),
              trust,
            })
          );
          expect(err.code).toBe(want);
          expect(trust.exportState()).toEqual(new IdentityRegistry().exportState());
          return;
        }

        const first = { header: libraryHeader(sc.first_message.header), ciphertext_b64: hexToB64(sc.first_message.ciphertext_hex) };
        if (r.sk_hex) {
          const state = ratchetInitResponderV2({
            sk32: unhex(r.sk_hex),
            ad: unhex(r.ad_hex),
            selfSpk: { priv32: unhex(bob.spk.private_hex), pub32: unhex(bob.spk.public_hex) },
          });
          const before = JSON.stringify(serializeRatchetStateV2(state));
          expect(thrownBy(() => ratchetDecrypt({ state, ...first })).code).toBe(want);
          expect(JSON.stringify(serializeRatchetStateV2(state))).toBe(before);
          return;
        }

        const prekeys = partyPrekeys(bob, r.prekeys_held ?? {});
        const before = JSON.stringify(prekeys.exportState());
        const err = thrownBy(() => {
          const boot = x3dhResponderBootstrapV2({
            session_init: librarySessionInit(r.session_init),
            prekeys,
            recipient_device_id: bob.device_id,
            sender_device_id: r.sender_device_id,
          });
          if (r.deliver !== "first_message") throw new Error("the bootstrap was expected to refuse");
          ratchetDecrypt({ state: boot.ratchet_state, ...first });
        });
        expect(err.code).toBe(want);
        expect(JSON.stringify(prekeys.exportState())).toBe(before);
      });
    }
  }

  it("ad_builder: the layout, and every refusal with its code", () => {
    for (const c of file.ad_builder) {
      const build = () =>
        buildAssociatedDataV2({
          initiator_ik_pub32: unhex(c.input.ik_a_hex),
          responder_ik_pub32: unhex(c.input.ik_b_hex),
          initiator_ik_sig_pub32: unhex(c.input.ik_sig_a_hex),
          responder_ik_sig_pub32: unhex(c.input.ik_sig_b_hex),
          initiator_device_id: c.input.dev_a,
          responder_device_id: c.input.dev_b,
        });
      if (c.expected_code) expect(thrownBy(build).code, c.name).toBe(c.expected_code);
      else expect(hex(build()), c.name).toBe(c.ad_hex);
    }
  });

  it("every null-code refusal has a library code", () => {
    const nulls = file.scenarios.flatMap((s: any) => s.refusals).filter((r: any) => r.expected_code === null);
    expect(nulls.map((r: any) => r.name).sort()).toEqual(Object.keys(ASSIGNED).sort());
  });
});

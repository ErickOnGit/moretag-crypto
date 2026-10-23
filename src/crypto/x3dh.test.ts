import { describe, it, expect } from "vitest";
import {
  buildOpkBatchSigMessage,
  buildSpkSigMessage,
  verifyPrekeyBundleV2,
  x3dhInitiatorV2,
  x3dhResponderV2,
} from "./x3dh.js";
import { generateX25519Keypair, x25519SharedSecret } from "./x25519.js";
import { generateEd25519Keypair, ed25519Sign } from "./ed25519.js";
import { hkdfSha256 } from "./hkdf.js";
import { parseAssociatedDataV2 } from "./ad.js";
import { bytesToBase64, decodeStrictBase64 } from "../encoding/base64.js";
import {
  BadSignatureError,
  DeviceMismatchError,
  InvalidDeviceIdError,
  InvalidWireError,
  LowOrderKeyError,
  SelfSessionError,
} from "../errors.js";
import { X3DH_ALG_V2, type X3DHPrekeyBundleV2, type X3DHSessionInitV2 } from "../wire/x3dh.js";
import { ALICE_DEVICE, BOB_DEVICE, CAROL_DEVICE } from "../test-fixtures.js";

function bob(opts: { withOpk?: boolean; deviceId?: string; spkId?: number } = {}) {
  const deviceId = opts.deviceId ?? BOB_DEVICE;
  const spkId = opts.spkId ?? 7;
  const ik = generateX25519Keypair();
  const ikSig = generateEd25519Keypair();
  const spk = generateX25519Keypair();
  const opk = generateX25519Keypair();
  const bundle: X3DHPrekeyBundleV2 = {
    v: 2,
    alg: X3DH_ALG_V2,
    recipient_device_id: deviceId,
    ik_pub_b64: bytesToBase64(ik.pub32),
    ik_sig_pub_b64: bytesToBase64(ikSig.pub32),
    spk_pub_b64: bytesToBase64(spk.pub32),
    spk_id: spkId,
    spk_sig_b64: bytesToBase64(
      ed25519Sign(
        ikSig.priv32,
        buildSpkSigMessage({ recipient_device_id: deviceId, ik_pub32: ik.pub32, spk_pub32: spk.pub32, spk_id: spkId })
      )
    ),
    ...(opts.withOpk ? { opk_id: 300, opk_pub_b64: bytesToBase64(opk.pub32) } : {}),
  };
  return { ik, ikSig, spk, opk, bundle };
}

function alice() {
  return { ik: generateX25519Keypair(), ikSig: generateEd25519Keypair() };
}

function initiate(a: ReturnType<typeof alice>, bundle: X3DHPrekeyBundleV2, expected = BOB_DEVICE) {
  return x3dhInitiatorV2({
    sender_device_id: ALICE_DEVICE,
    recipient_bundle: bundle,
    expected_recipient_device_id: expected,
    initiator_ik_priv32: a.ik.priv32,
    initiator_ik_sig_pub32: a.ikSig.pub32,
  });
}

function respond(b: ReturnType<typeof bob>, session_init: X3DHSessionInitV2, withOpk = false) {
  return x3dhResponderV2({
    session_init,
    sender_device_id: ALICE_DEVICE,
    recipient_device_id: BOB_DEVICE,
    recipient_ik_priv32: b.ik.priv32,
    recipient_ik_sig_pub32: b.ikSig.pub32,
    recipient_spk_priv32: b.spk.priv32,
    ...(withOpk ? { recipient_opk_priv32: b.opk.priv32 } : {}),
  });
}

function thrownBy(fn: () => unknown): unknown {
  try {
    fn();
  } catch (err) {
    return err;
  }
  throw new Error("expected a throw");
}

describe("X3DH v2", () => {
  it.each([false, true])("both sides derive the same SK and AD (one-time prekey: %s)", (withOpk) => {
    const a = alice();
    const b = bob({ withOpk });
    const init = initiate(a, b.bundle);
    const resp = respond(b, init.session_init, withOpk);
    expect(resp.sk32).toEqual(init.sk32);
    expect(resp.ad).toEqual(init.ad);

    const parsed = parseAssociatedDataV2(init.ad);
    expect(parsed).toEqual({
      initiator_ik_pub32: a.ik.pub32,
      responder_ik_pub32: b.ik.pub32,
      initiator_ik_sig_pub32: a.ikSig.pub32,
      responder_ik_sig_pub32: b.ikSig.pub32,
      initiator_device_id: ALICE_DEVICE,
      responder_device_id: BOB_DEVICE,
    });
  });

  it.each([false, true])("SK = HKDF(salt 0^32, F || DH1 || DH2 || DH3 [|| DH4], 'moretag/x3dh/v2'), and differs without F (opk: %s)", (withOpk) => {
    const a = alice();
    const b = bob({ withOpk });
    const init = initiate(a, b.bundle);
    const ek = decodeStrictBase64("ek", init.session_init.ek_pub_b64);
    const dhs = [
      x25519SharedSecret(b.spk.priv32, a.ik.pub32),
      x25519SharedSecret(b.ik.priv32, ek),
      x25519SharedSecret(b.spk.priv32, ek),
      ...(withOpk ? [x25519SharedSecret(b.opk.priv32, ek)] : []),
    ];
    const concat = (parts: Uint8Array[]) => {
      const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
      let at = 0;
      for (const p of parts) {
        out.set(p, at);
        at += p.length;
      }
      return out;
    };
    const info = new TextEncoder().encode("moretag/x3dh/v2");
    const km = concat([new Uint8Array(32).fill(0xff), ...dhs]);
    expect(km.length).toBe(withOpk ? 160 : 128);
    expect(hkdfSha256(km, new Uint8Array(32), info, 32)).toEqual(init.sk32);
    expect(hkdfSha256(concat(dhs), new Uint8Array(32), info, 32)).not.toEqual(init.sk32);
  });

  it("the session_init carries both identity keys, the EK and the prekey ids", () => {
    const a = alice();
    const withOpk = initiate(a, bob({ withOpk: true }).bundle).session_init;
    expect(withOpk).toMatchObject({
      v: 2,
      alg: X3DH_ALG_V2,
      sender_device_id: ALICE_DEVICE,
      recipient_device_id: BOB_DEVICE,
      sender_ik_pub_b64: bytesToBase64(a.ik.pub32),
      sender_ik_sig_pub_b64: bytesToBase64(a.ikSig.pub32),
      spk_id: 7,
      used_opk: true,
      opk_id: 300,
    });
    const noOpk = initiate(a, bob().bundle).session_init;
    expect(noOpk.used_opk).toBe(false);
    expect(noOpk).not.toHaveProperty("opk_id");
  });

  it("a fresh EK per setup", () => {
    const a = alice();
    const b = bob();
    expect(initiate(a, b.bundle).session_init.ek_pub_b64).not.toBe(initiate(a, b.bundle).session_init.ek_pub_b64);
  });

  it("a missing initiator Ed25519 key is refused on both sides", () => {
    const a = alice();
    const b = bob();
    expect(() =>
      x3dhInitiatorV2({
        sender_device_id: ALICE_DEVICE,
        recipient_bundle: b.bundle,
        expected_recipient_device_id: BOB_DEVICE,
        initiator_ik_priv32: a.ik.priv32,
        initiator_ik_sig_pub32: undefined as never,
      })
    ).toThrow(TypeError);
    const { sender_ik_sig_pub_b64: _dropped, ...noSig } = initiate(a, b.bundle).session_init;
    const err = thrownBy(() => respond(b, noSig as X3DHSessionInitV2));
    expect((err as InvalidWireError).code).toBe("invalid_session_init");
  });

  it("opk_id without used_opk, and used_opk without opk_id, are refused", () => {
    const a = alice();
    const b = bob({ withOpk: true });
    const si = initiate(a, b.bundle).session_init;
    for (const bad of [{ ...si, used_opk: false }, { ...si, opk_id: undefined }]) {
      expect((thrownBy(() => respond(b, bad as X3DHSessionInitV2, true)) as InvalidWireError).code).toBe(
        "invalid_session_init"
      );
    }
  });

  it("session_init ids, keys and version are checked", () => {
    const a = alice();
    const b = bob();
    const si = initiate(a, b.bundle).session_init;
    const rows: Array<[unknown, string]> = [
      [{ ...si, v: 1 }, "invalid_session_init"],
      [{ ...si, alg: "x" }, "invalid_session_init"],
      [{ ...si, spk_id: 0 }, "invalid_session_init"],
      [{ ...si, spk_id: 2 ** 31 }, "invalid_session_init"],
      [{ ...si, spk_id: "7" }, "invalid_session_init"],
      [{ ...si, ek_pub_b64: bytesToBase64(new Uint8Array(31)) }, "invalid_session_init"],
      [{ ...si, sender_ik_pub_b64: "AAAA" }, "invalid_session_init"],
      [{ ...si, sender_device_id: ALICE_DEVICE.toUpperCase() }, "invalid_device_id"],
    ];
    for (const [bad, code] of rows) {
      expect((thrownBy(() => respond(b, bad as X3DHSessionInitV2)) as InvalidWireError).code).toBe(code);
    }
  });

  it("a sidecar naming another sender than the row, or another recipient, is device_mismatch", () => {
    const a = alice();
    const b = bob();
    const si = initiate(a, b.bundle).session_init;
    expect(thrownBy(() => respond(b, { ...si, sender_device_id: CAROL_DEVICE }))).toBeInstanceOf(DeviceMismatchError);
    expect(thrownBy(() => respond(b, { ...si, recipient_device_id: CAROL_DEVICE }))).toBeInstanceOf(DeviceMismatchError);
  });

  it("equal device ids are self_session", () => {
    const a = alice();
    const b = bob();
    const si = initiate(a, b.bundle).session_init;
    expect(
      thrownBy(() =>
        x3dhResponderV2({
          session_init: { ...si, sender_device_id: BOB_DEVICE },
          sender_device_id: BOB_DEVICE,
          recipient_device_id: BOB_DEVICE,
          recipient_ik_priv32: b.ik.priv32,
          recipient_ik_sig_pub32: b.ikSig.pub32,
          recipient_spk_priv32: b.spk.priv32,
        })
      )
    ).toBeInstanceOf(SelfSessionError);
    const self = bob({ deviceId: ALICE_DEVICE });
    expect(thrownBy(() => initiate(a, self.bundle, ALICE_DEVICE))).toBeInstanceOf(SelfSessionError);
  });

  it("a low-order EK is refused with low_order_key", () => {
    const a = alice();
    const b = bob();
    const si = initiate(a, b.bundle).session_init;
    for (const u of [new Uint8Array(32), Uint8Array.from({ length: 32 }, (_, i) => (i === 0 ? 1 : 0))]) {
      const err = thrownBy(() => respond(b, { ...si, ek_pub_b64: bytesToBase64(u) }));
      expect(err).toBeInstanceOf(LowOrderKeyError);
      expect((err as LowOrderKeyError).code).toBe("low_order_key");
    }
  });
});

describe("bundle verification (initiator order: signature, then device)", () => {
  it("a bundle naming another device is device_mismatch", () => {
    const err = thrownBy(() => initiate(alice(), bob({ deviceId: CAROL_DEVICE }).bundle));
    expect(err).toBeInstanceOf(DeviceMismatchError);
  });

  it("a replaced SPK, a wrong signer or a changed spk_id is bad_signature", () => {
    const b = bob();
    const other = generateEd25519Keypair();
    const bad: X3DHPrekeyBundleV2[] = [
      { ...b.bundle, spk_pub_b64: bytesToBase64(generateX25519Keypair().pub32) },
      { ...b.bundle, ik_sig_pub_b64: bytesToBase64(other.pub32) },
      { ...b.bundle, spk_id: 8 },
      { ...b.bundle, ik_pub_b64: bytesToBase64(generateX25519Keypair().pub32) },
    ];
    for (const bundle of bad) {
      const err = thrownBy(() => initiate(alice(), bundle));
      expect(err).toBeInstanceOf(BadSignatureError);
      expect((err as BadSignatureError).code).toBe("bad_signature");
    }
  });

  it("a badly signed bundle for another device is bad_signature, not device_mismatch", () => {
    const b = bob({ deviceId: CAROL_DEVICE });
    const bundle = { ...b.bundle, spk_pub_b64: bytesToBase64(generateX25519Keypair().pub32) };
    expect(thrownBy(() => verifyPrekeyBundleV2(bundle, BOB_DEVICE))).toBeInstanceOf(BadSignatureError);
  });

  it("shape: version, ids, lengths, the one-time prekey pair and canonical device ids", () => {
    const b = bob({ withOpk: true });
    const rows: Array<[unknown, string]> = [
      [{ ...b.bundle, v: 1 }, "invalid_bundle"],
      [{ ...b.bundle, spk_id: 1.5 }, "invalid_bundle"],
      [{ ...b.bundle, spk_sig_b64: bytesToBase64(new Uint8Array(63)) }, "invalid_bundle"],
      [{ ...b.bundle, opk_id: undefined }, "invalid_bundle"],
      [{ ...b.bundle, opk_pub_b64: undefined }, "invalid_bundle"],
      [{ ...b.bundle, opk_id: 0 }, "invalid_bundle"],
      [{ ...b.bundle, recipient_device_id: "device-123" }, "invalid_device_id"],
    ];
    for (const [bad, code] of rows) {
      expect((thrownBy(() => verifyPrekeyBundleV2(bad as X3DHPrekeyBundleV2, BOB_DEVICE)) as InvalidWireError).code).toBe(code);
    }
    expect(thrownBy(() => verifyPrekeyBundleV2(b.bundle, "bob"))).toBeInstanceOf(InvalidDeviceIdError);
  });
});

describe("signing messages", () => {
  it("the SPK message is CBOR [domain, device_id, IK, SPK, spk_id]", () => {
    const msg = buildSpkSigMessage({
      recipient_device_id: BOB_DEVICE,
      ik_pub32: new Uint8Array(32).fill(1),
      spk_pub32: new Uint8Array(32).fill(2),
      spk_id: 300,
    });
    expect(Buffer.from(msg).toString("hex")).toBe(
      "85" +
        "73" + Buffer.from("moretag/x3dh/spk/v1").toString("hex") +
        "7824" + Buffer.from(BOB_DEVICE).toString("hex") +
        "5820" + "01".repeat(32) +
        "5820" + "02".repeat(32) +
        "19012c"
    );
  });

  it("the batch message is CBOR [domain, device_id, [[id, key], ...]] in the order given", () => {
    const msg = buildOpkBatchSigMessage({
      device_id: BOB_DEVICE,
      prekeys: [
        { opk_id: 2, pub32: new Uint8Array(32).fill(2) },
        { opk_id: 1, pub32: new Uint8Array(32).fill(1) },
      ],
    });
    expect(Buffer.from(msg).toString("hex")).toBe(
      "83" +
        "7819" + Buffer.from("moretag/x3dh/opk-batch/v1").toString("hex") +
        "7824" + Buffer.from(BOB_DEVICE).toString("hex") +
        "82" + "82" + "02" + "5820" + "02".repeat(32) + "82" + "01" + "5820" + "01".repeat(32)
    );
  });

  it("the batch message refuses duplicate or out-of-range ids and non-canonical device ids", () => {
    const key = new Uint8Array(32);
    for (const prekeys of [
      [{ opk_id: 1, pub32: key }, { opk_id: 1, pub32: key }],
      [{ opk_id: 0, pub32: key }],
      [{ opk_id: 2 ** 31, pub32: key }],
      [{ opk_id: 1, pub32: new Uint8Array(31) }],
    ]) {
      expect(() => buildOpkBatchSigMessage({ device_id: BOB_DEVICE, prekeys })).toThrow(TypeError);
    }
    expect(() => buildOpkBatchSigMessage({ device_id: "bob", prekeys: [] })).toThrow(InvalidDeviceIdError);
  });
});

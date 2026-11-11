#!/usr/bin/env node
// Independent known-answer vectors for the device proof and the pairing code.
//
// Computes:
//   vectors/device-proof-v1.json  Ed25519 device proofs over the CBOR array of
//                                 docs/SPEC.md §4.5, verification outcomes
//                                 (valid / bad_signature / expired) and build
//                                 inputs that must refuse.
//   vectors/device-code-v1.json   six-digit pairing codes of IKsig public keys.
//
// Imports only node:crypto, node:fs and node:path. It never imports the library
// (src/, dist/), its vectors or its other scripts. The author worked only from
// docs/SPEC.md §2 (CBOR row), §3 (device ids) and §4.5, and from the public texts
// RFC 8032 (Ed25519), RFC 8949 (CBOR) and FIPS 180-4 (SHA-256), and read no
// library source. Where §4.5 was silent, the reading taken is in PARAMS.readings.
//
// Usage:
//   node scripts/gen-vectors-device-v1.mjs --write   self-check, then write
//   node scripts/gen-vectors-device-v1.mjs --check   self-check, regenerate in
//                                                    memory, compare with disk

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const PARAMS = {
  secret_rule: 'secret(label) = SHA-256(UTF-8("moretag-crypto/vectors/device/v1/" || label))',
  uuid_rule: 'uuid(label) = first 16 bytes of secret(label), printed canonical lowercase 8-4-4-4-12; no version or variant bits set (SPEC §3: not checked)',
  ed25519_rule: 'an Ed25519 seed is a 32-byte secret; public key per RFC 8032 §5.1.5',
  proof_domain: 'moretag/device-proof/v1',
  code_domain: 'moretag/device-code/v1',
  max_skew_s: 300,
  readings: [
    'R1. Absent target fields: for remove/reset/refresh "every other action: empty (0 bytes)" and for reset/refresh target_device_id "" (§4.5 table). A field omitted from `fields` is put on the wire as the text "" or the empty byte string.',
    'R2. §4.5: "`\\"\\"` and an empty key are the absent values: given where no target belongs, they build the same bytes as leaving them out." Read further: given where a target belongs (target id for approve/remove, key for approve) they are also absent, so the target is "missing" (type_error), not a non-canonical device id.',
    'R3. "a session id that is not a canonical UUID ... is a `TypeError`": the session id refuses with type_error, never invalid_device_id (it is not a device id).',
    'R4. "a device id that is not canonical is `invalid_device_id`" covers both acting_device_id and target_device_id when a non-empty target id is given where one is required (approve, remove).',
    'R5. issued_at_s must be a JSON/JS number that is a safe integer >= 0; a string, a fraction, a negative number or 2^53 is type_error. Times of 2^32 and above use the 8-byte CBOR head (§2: "integers of 2^32 and above as integers").',
    'R6. Pairing code input: the UTF-8 bytes of "moretag/device-code/v1" directly followed by the 32 raw IKsig bytes, no separator or length prefix; the IKsig must be exactly 32 bytes, else type_error.',
    'R7. Verification rebuilds the message from the verifier fields; a signature of any length other than 64 is bad_signature (not a TypeError), and the signature is checked before the time, so a bad and stale proof is bad_signature.',
    'R8. The target key for approve is checked only for length (32 bytes), not as a curve point; §4.5 states only the length.',
    'R9. Verifier key rule (given by the coordinator as new §4.5 text; not present in the §4.5 the author read): an acting key that is not 32 bytes is type_error; one that does not decode canonically (RFC 8032 §5.1.3: y >= p, or x = 0 with the sign bit set, or no square root) or decodes to a point of small order ([8]P = identity) is bad_signature, checked before the signature. Small order is computed here with RFC 8032 §5.1.4 point arithmetic, not taken from a list.',
    'R10. now_s must be a safe integer >= 0, else the verifier throws type_error (given by the coordinator; not present in the §4.5 the author read). Checked before everything else.',
  ],
};

const VECTORS_DIR = path.resolve(import.meta.dirname, '..', 'vectors');
const PROOF_FILE = path.join(VECTORS_DIR, 'device-proof-v1.json');
const CODE_FILE = path.join(VECTORS_DIR, 'device-code-v1.json');

// ---------- primitives ----------

const hex = (b) => Buffer.from(b).toString('hex');
const unhex = (h) => Buffer.from(h, 'hex');
const sha256 = (...parts) => {
  const h = crypto.createHash('sha256');
  for (const p of parts) h.update(p);
  return h.digest();
};

const SECRET_PREFIX = 'moretag-crypto/vectors/device/v1/';
const secret = (label) => sha256(Buffer.from(SECRET_PREFIX + label, 'utf8'));

function uuidFromLabel(label) {
  const h = hex(secret(label).subarray(0, 16));
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20, 32)}`;
}

const PKCS8_PREFIX = unhex('302e020100300506032b657004220420');
function privKey(seed) {
  if (seed.length !== 32) throw new Error('seed must be 32 bytes');
  return crypto.createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, seed]), format: 'der', type: 'pkcs8' });
}
function pubFromSeed(seed) {
  const spki = crypto.createPublicKey(privKey(seed)).export({ format: 'der', type: 'spki' });
  return Buffer.from(spki.subarray(spki.length - 32));
}
const SPKI_PREFIX = unhex('302a300506032b6570032100');
function pubKeyObj(pub) {
  return crypto.createPublicKey({ key: Buffer.concat([SPKI_PREFIX, pub]), format: 'der', type: 'spki' });
}
const sign = (seed, msg) => crypto.sign(null, msg, privKey(seed));
function verifySig(pub, msg, sig) {
  if (sig.length !== 64) return false;
  try {
    return crypto.verify(null, msg, pubKeyObj(pub), sig);
  } catch {
    return false;
  }
}

// ---------- CBOR (RFC 8949, deterministic shortest form, §4.2.1) ----------

function cborHead(major, n) {
  let v = typeof n === 'bigint' ? n : BigInt(n);
  if (v < 0n || v > 0xffffffffffffffffn) throw new Error('cbor: argument out of range');
  const m = major << 5;
  if (v < 24n) return Buffer.from([m | Number(v)]);
  if (v < 0x100n) return Buffer.from([m | 24, Number(v)]);
  if (v < 0x10000n) { const b = Buffer.alloc(3); b[0] = m | 25; b.writeUInt16BE(Number(v), 1); return b; }
  if (v < 0x100000000n) { const b = Buffer.alloc(5); b[0] = m | 26; b.writeUInt32BE(Number(v), 1); return b; }
  const b = Buffer.alloc(9); b[0] = m | 27; b.writeBigUInt64BE(v, 1); return b;
}

function cbor(value) {
  if (typeof value === 'bigint') {
    if (value < 0n) throw new Error('cbor: negative integers refused');
    return cborHead(0, value);
  }
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) throw new Error('cbor: only safe unsigned integers as numbers');
    return cborHead(0, value);
  }
  if (typeof value === 'string') {
    if (!value.isWellFormed()) throw new Error('cbor: ill-formed string');
    const b = Buffer.from(value, 'utf8');
    return Buffer.concat([cborHead(3, b.length), b]);
  }
  if (value instanceof Uint8Array) {
    return Buffer.concat([cborHead(2, value.length), Buffer.from(value)]);
  }
  if (Array.isArray(value)) {
    return Buffer.concat([cborHead(4, value.length), ...value.map(cbor)]);
  }
  throw new Error(`cbor: unsupported type ${typeof value}`);
}

// ---------- self-check ----------

function selfCheck() {
  const fails = [];
  const eq = (name, got, want) => { if (got !== want) fails.push(`${name}: got ${got}, want ${want}`); };

  // RFC 8032 §7.1, TEST 1 (empty message), copied by hand from the RFC.
  const t1Secret = unhex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60');
  const t1Public = 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a';
  const t1Sig = 'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b';
  eq('RFC 8032 §7.1 test 1 public', hex(pubFromSeed(t1Secret)), t1Public);
  eq('RFC 8032 §7.1 test 1 signature', hex(sign(t1Secret, Buffer.alloc(0))), t1Sig);
  eq('RFC 8032 §7.1 test 1 verifies', String(verifySig(unhex(t1Public), Buffer.alloc(0), unhex(t1Sig))), 'true');

  // RFC 8032 §5.1: the base point B (y = 4/5, x from the RFC) decodes from its
  // encoding 58 66..66, has order neither small, and test 1's key is not small.
  const B = decodePoint(unhex('58' + '66'.repeat(31)));
  eq('RFC 8032 §5.1 base point x', String(B && B[0]), '15112221349535400772501151409588531511454012693041857206046113283949847762202');
  eq('RFC 8032 §5.1 base point y', String(B && B[1]), String(mod(4n * inv(5n))));
  eq('base point not small order', String(B && isSmallOrder(B)), 'false');
  eq('test 1 key not small order', String(isSmallOrder(decodePoint(unhex(t1Public)))), 'false');

  // FIPS 180-4 / NIST example: SHA-256("abc").
  eq('SHA-256("abc")', hex(sha256(Buffer.from('abc'))), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');

  // RFC 8949 Appendix A.
  const appA = [
    [0, '00'], [23, '17'], [24, '1818'], [100, '1864'], [1000, '1903e8'],
    [1000000, '1a000f4240'], [1000000000000, '1b000000e8d4a51000'],
    [18446744073709551615n, '1bffffffffffffffff'],
    ['', '60'], ['a', '6161'], [new Uint8Array(0), '40'],
    [unhex('01020304'), '4401020304'], [[], '80'], [[1, 2, 3], '83010203'],
  ];
  for (const [v, want] of appA) eq(`RFC 8949 App. A ${typeof v === 'bigint' ? v.toString() : JSON.stringify(v instanceof Uint8Array ? `h'${hex(v)}'` : v)}`, hex(cbor(v)), want);
  for (const bad of [-1, 1.5, 2 ** 53, null, {}, true]) {
    try { cbor(bad); fails.push(`cbor accepted ${JSON.stringify(bad)}`); } catch { /* refused */ }
  }
  if (fails.length) {
    console.error('SELF-CHECK FAILED:\n  ' + fails.join('\n  '));
    process.exit(1);
  }
}

// ---------- edwards25519 (RFC 8032 §5.1), BigInt, for the key checks ----------

const P = 2n ** 255n - 19n;
const mod = (a) => ((a % P) + P) % P;
function powmod(b, e) { let r = 1n; b = mod(b); while (e > 0n) { if (e & 1n) r = r * b % P; b = b * b % P; e >>= 1n; } return r; }
const inv = (a) => powmod(a, P - 2n);
const D = mod(-121665n * inv(121666n));
const SQRT_M1 = powmod(2n, (P - 1n) / 4n);
// RFC 8032 §5.1.3 decoding; null when the encoding is not canonical or not on the curve.
function decodePoint(b) {
  const bytes = Buffer.from(b);
  const sign = bytes[31] >> 7;
  bytes[31] &= 0x7f;
  const y = BigInt('0x' + hex(Buffer.from(bytes).reverse()));
  if (y >= P) return null;
  const u = mod(y * y - 1n);
  const v = mod(D * y * y + 1n);
  let x = mod(u * powmod(v, 3n) * powmod(u * powmod(v, 7n), (P - 5n) / 8n));
  const vx2 = mod(v * x * x);
  if (vx2 === mod(-u)) x = mod(x * SQRT_M1);
  else if (vx2 !== u) return null;
  if (x === 0n && sign === 1) return null;
  if (Number(x & 1n) !== sign) x = mod(-x);
  return [x, y];
}
function add([x1, y1], [x2, y2]) {
  const t = mod(D * x1 * x2 * y1 * y2);
  return [mod((x1 * y2 + x2 * y1) * inv(1n + t)), mod((y1 * y2 + x1 * x2) * inv(1n - t))];
}
const dbl = (p) => add(p, p);
const isIdentity = ([x, y]) => x === 0n && y === 1n;
const isSmallOrder = (p) => isIdentity(dbl(dbl(dbl(p))));
function orderOfSmall(p) { let q = p; for (let k = 1; k <= 8; k++) { if (isIdentity(q)) return k; q = add(q, p); } return null; }

// ---------- device proof (reference reading of SPEC §4.5) ----------

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const ACTIONS = ['approve', 'remove', 'reset', 'refresh'];

class Refusal extends Error {
  constructor(code, msg) { super(msg); this.code = code; }
}
const typeErr = (m) => { throw new Refusal('type_error', m); };
const devErr = (m) => { throw new Refusal('invalid_device_id', m); };
const has = (o, k) => Object.prototype.hasOwnProperty.call(o, k);

// fields: {action, acting_device_id, session_id, issued_at_s, target_device_id?, target_ik_sig_pub_hex?}
function buildParts(fields) {
  const { action, acting_device_id: acting, session_id: session, issued_at_s: t } = fields;
  if (typeof action !== 'string' || !ACTIONS.includes(action)) typeErr('unknown action');
  if (typeof acting !== 'string' || !UUID_RE.test(acting)) devErr('acting id');
  if (typeof session !== 'string' || !UUID_RE.test(session)) typeErr('session id');
  if (typeof t !== 'number' || !Number.isSafeInteger(t) || t < 0) typeErr('issued_at_s');
  // R2: "" and an empty key are the absent values.
  const hasId = has(fields, 'target_device_id') && fields.target_device_id !== '';
  const hasKey = has(fields, 'target_ik_sig_pub_hex') && fields.target_ik_sig_pub_hex !== '';
  let targetId = '';
  let targetKey = Buffer.alloc(0);
  if (action === 'approve' || action === 'remove') {
    if (!hasId) typeErr('missing target id');
    if (typeof fields.target_device_id !== 'string' || !UUID_RE.test(fields.target_device_id)) devErr('target id');
    targetId = fields.target_device_id;
    if (action === 'approve') {
      if (targetId === acting) typeErr('approval of the acting device');
      if (!hasKey) typeErr('missing target key');
      targetKey = unhex(fields.target_ik_sig_pub_hex);
      if (targetKey.length !== 32) typeErr('target key length');
    } else if (hasKey) typeErr('extra target key');
  } else {
    if (hasId) typeErr('extra target id');
    if (hasKey) typeErr('extra target key');
  }
  const elems = [PARAMS.proof_domain, action, acting, session, t, targetId, targetKey];
  return { elems, parts: [cborHead(4, elems.length), ...elems.map(cbor)] };
}
const buildMessage = (fields) => Buffer.concat(buildParts(fields).parts);

function verifyProof(fields, storedPub, sig, nowS) {
  if (typeof nowS !== 'number' || !Number.isSafeInteger(nowS) || nowS < 0) typeErr('now_s');
  if (!(storedPub instanceof Uint8Array) || storedPub.length !== 32) typeErr('acting key length');
  const msg = buildMessage(fields);
  const A = decodePoint(storedPub);
  if (A === null || isSmallOrder(A)) return 'bad_signature';
  if (!verifySig(storedPub, msg, sig)) return 'bad_signature';
  if (Math.abs(nowS - fields.issued_at_s) > PARAMS.max_skew_s) return 'expired';
  return 'valid';
}

// ---------- generation ----------

function party(name) {
  const idLabel = `party/${name}/device_id`;
  const seedLabel = `party/${name}/ik_sig_seed`;
  const seed = secret(seedLabel);
  return {
    device_id: uuidFromLabel(idLabel),
    device_id_label: idLabel,
    ik_sig_seed_label: seedLabel,
    ik_sig_seed_hex: hex(seed),
    ik_sig_public_hex: hex(pubFromSeed(seed)),
  };
}

function genProof() {
  const parties = { acting: party('acting'), target: party('target'), other: party('other') };
  const sessionLabel = 'session/main';
  const otherSessionLabel = 'session/other';
  const session = uuidFromLabel(sessionLabel);
  const otherSession = uuidFromLabel(otherSessionLabel);
  const A = parties.acting;
  const T = parties.target;
  const O = parties.other;
  const NOW = 1762560000;

  const base = { acting_device_id: A.device_id, session_id: session };
  const valid = [];
  const byName = {};
  const addValid = (name, fields, withParts = false) => {
    const { elems, parts } = buildParts(fields);
    const msg = Buffer.concat(parts);
    const sig = sign(unhex(A.ik_sig_seed_hex), msg);
    if (!verifySig(unhex(A.ik_sig_public_hex), msg, sig)) throw new Error(`own signature fails: ${name}`);
    const c = { name, fields, message_cbor_hex: hex(msg), signature_hex: hex(sig) };
    if (withParts) {
      const labels = ['array(7)', 'domain', 'action', 'acting_device_id', 'session_id', 'issued_at_s', 'target_device_id', 'target_ik_sig_pub'];
      c.message_parts_hex = parts.map((p, i) => ({ part: labels[i], hex: hex(p) }));
    }
    valid.push(c);
    byName[name] = c;
  };

  addValid('approve', { action: 'approve', ...base, issued_at_s: NOW, target_device_id: T.device_id, target_ik_sig_pub_hex: T.ik_sig_public_hex }, true);
  addValid('remove', { action: 'remove', ...base, issued_at_s: NOW, target_device_id: T.device_id }, true);
  addValid('reset', { action: 'reset', ...base, issued_at_s: NOW }, true);
  addValid('refresh', { action: 'refresh', ...base, issued_at_s: NOW });
  // R2: explicit "" target id on reset builds the same message as reset.
  addValid('reset_explicit_empty_target_id', { action: 'reset', ...base, issued_at_s: NOW, target_device_id: '' });
  addValid('remove_explicit_empty_target_key', { action: 'remove', ...base, issued_at_s: NOW, target_device_id: T.device_id, target_ik_sig_pub_hex: '' });
  addValid('refresh_explicit_empty_target_id', { action: 'refresh', ...base, issued_at_s: NOW, target_device_id: '' });
  addValid('refresh_explicit_empty_target_key', { action: 'refresh', ...base, issued_at_s: NOW, target_ik_sig_pub_hex: '' });
  for (const [a, b] of [['reset_explicit_empty_target_id', 'reset'], ['remove_explicit_empty_target_key', 'remove'], ['refresh_explicit_empty_target_id', 'refresh'], ['refresh_explicit_empty_target_key', 'refresh']]) {
    if (byName[a].message_cbor_hex !== byName[b].message_cbor_hex) throw new Error(`R2 bytes differ: ${a}`);
  }

  const widths = [0, 23, 24, 255, 256, 65535, 65536, 4294967295, 4294967296, 9007199254740991];
  widths.forEach((t, i) => {
    const action = i % 2 === 0 ? 'remove' : 'reset';
    const f = { action, ...base, issued_at_s: t };
    if (action === 'remove') f.target_device_id = T.device_id;
    addValid(`${action}_issued_at_${t}`, f, t === 24 || t === 4294967296);
  });

  // ---- verify ----
  const signerPub = { acting: A.ik_sig_public_hex, target: T.ik_sig_public_hex, other: O.ik_sig_public_hex };
  const verify = [];
  const addVerify = (name, baseName, { overrides = {}, signer = 'acting', signerHex, now_s, sig, expect, note }) => {
    if (signerHex !== undefined) signerPub[signer] = signerHex;
    const b = byName[baseName];
    const fields = { ...b.fields };
    for (const [k, v] of Object.entries(overrides)) {
      if (v === null) delete fields[k]; else fields[k] = v;
    }
    const sigHex = sig ?? b.signature_hex;
    const got = verifyProof(fields, unhex(signerPub[signer]), unhex(sigHex), now_s);
    if (got !== expect) throw new Error(`verify ${name}: got ${got}, want ${expect}`);
    verify.push({
      name,
      base: baseName,
      verifier: { fields: overrides, signer, signer_ik_sig_public_hex: signerPub[signer], now_s },
      signature_hex: sigHex,
      expect,
      ...(note ? { note } : {}),
    });
  };
  const flip = (h) => { const b = unhex(h); b[10] ^= 0x01; return hex(b); };

  addVerify('same_fields_now_equal', 'approve', { now_s: NOW, expect: 'valid' });
  addVerify('now_plus_300', 'approve', { now_s: NOW + 300, expect: 'valid' });
  addVerify('now_minus_300', 'approve', { now_s: NOW - 300, expect: 'valid' });
  addVerify('now_plus_301', 'approve', { now_s: NOW + 301, expect: 'expired' });
  addVerify('now_minus_301', 'approve', { now_s: NOW - 301, expect: 'expired' });
  addVerify('reset_now_plus_301', 'reset', { now_s: NOW + 301, expect: 'expired' });
  addVerify('max_time_valid', 'reset_issued_at_9007199254740991', { now_s: 9007199254740991 - 300, expect: 'valid' });
  addVerify('other_session', 'approve', { overrides: { session_id: otherSession }, now_s: NOW, expect: 'bad_signature' });
  addVerify('other_action_remove_for_approve', 'approve', { overrides: { action: 'remove', target_ik_sig_pub_hex: null }, now_s: NOW, expect: 'bad_signature' });
  addVerify('other_action_refresh_for_reset', 'reset', { overrides: { action: 'refresh' }, now_s: NOW, expect: 'bad_signature' });
  addVerify('other_acting_device_id', 'approve', { overrides: { acting_device_id: O.device_id }, now_s: NOW, expect: 'bad_signature' });
  addVerify('other_target_id_approve', 'approve', { overrides: { target_device_id: O.device_id }, now_s: NOW, expect: 'bad_signature' });
  addVerify('other_target_id_remove', 'remove', { overrides: { target_device_id: O.device_id }, now_s: NOW, expect: 'bad_signature' });
  addVerify('other_target_key_approve', 'approve', { overrides: { target_ik_sig_pub_hex: O.ik_sig_public_hex }, now_s: NOW, expect: 'bad_signature' });
  addVerify('other_time', 'reset', { overrides: { issued_at_s: NOW + 1 }, now_s: NOW, expect: 'bad_signature' });
  addVerify('key_of_other_device', 'approve', { signer: 'other', now_s: NOW, expect: 'bad_signature' });
  addVerify('key_of_target_device', 'approve', { signer: 'target', now_s: NOW, expect: 'bad_signature' });
  addVerify('flipped_signature_bit', 'approve', { now_s: NOW, sig: flip(byName.approve.signature_hex), expect: 'bad_signature' });
  addVerify('signature_63_bytes', 'approve', { now_s: NOW, sig: byName.approve.signature_hex.slice(0, 126), expect: 'bad_signature' });
  addVerify('signature_65_bytes', 'approve', { now_s: NOW, sig: byName.approve.signature_hex + '00', expect: 'bad_signature' });
  addVerify('signature_empty', 'reset', { now_s: NOW, sig: '', expect: 'bad_signature' });
  addVerify('bad_signature_and_stale', 'approve', { now_s: NOW + 301, sig: flip(byName.approve.signature_hex), expect: 'bad_signature' });
  addVerify('remove_checked_as_reset', 'remove', { overrides: { action: 'reset', target_device_id: null }, now_s: NOW, expect: 'bad_signature' });

  // R9: small-order and non-canonical acting keys.
  const ZERO32 = '00'.repeat(32);
  const ID_ENC = '01' + '00'.repeat(31);
  const idPt = decodePoint(unhex(ID_ENC));
  if (!idPt || !isIdentity(idPt)) throw new Error('identity decode');
  // An order-8 point: the canonical encoding listed as small-order in libsodium's
  // blocklist and in Chalkias, Garillot, Nikolaenko, "Taming the many EdDSAs"
  // (2020), Table 6; its order is recomputed here, not trusted.
  const ORD8_ENC = 'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a';
  const o8 = decodePoint(unhex(ORD8_ENC));
  if (!o8 || orderOfSmall(o8) !== 8) throw new Error('order-8 point check');
  // Non-canonical identity: y = p + 1 (>= p), little-endian, sign bit 0.
  const NONCANON_ID_ENC = hex(Buffer.from((P + 1n).toString(16).padStart(64, '0'), 'hex').reverse());
  if (decodePoint(unhex(NONCANON_ID_ENC)) !== null) throw new Error('non-canonical accepted');
  const zip215Note = 'R = the key encoding, S = 0: a cofactored (ZIP-215) verifier accepts it for any message';
  addVerify('small_order_identity_key', 'reset', { signer: 'identity_point', signerHex: ID_ENC, now_s: NOW, sig: ID_ENC + ZERO32, expect: 'bad_signature', note: `acting key = identity point (y = 1); ${zip215Note}` });
  addVerify('small_order_order8_key', 'reset', { signer: 'order8_point', signerHex: ORD8_ENC, now_s: NOW, sig: ORD8_ENC + ZERO32, expect: 'bad_signature', note: `acting key = an order-8 point (libsodium blocklist; Chalkias et al. 2020, "Taming the many EdDSAs"), order recomputed by the generator; ${zip215Note}` });
  addVerify('noncanonical_identity_key', 'reset', { signer: 'noncanonical_identity', signerHex: NONCANON_ID_ENC, now_s: NOW, sig: ID_ENC + ZERO32, expect: 'bad_signature', note: 'acting key = the identity with y = p + 1 (non-canonical, RFC 8032 §5.1.3 refuses y >= p); signature R = canonical identity, S = 0' });

  // R10 and the key length: inputs the verifier refuses by throwing.
  const verify_refusals = [];
  const addVerifyRefusal = (name, baseName, { keyHex = A.ik_sig_public_hex, now_s }) => {
    const b = byName[baseName];
    let got = 'returned';
    try { verifyProof({ ...b.fields }, unhex(keyHex), unhex(b.signature_hex), now_s); } catch (e) { if (!(e instanceof Refusal)) throw e; got = e.code; }
    if (got !== 'type_error') throw new Error(`verify refusal ${name}: got ${got}`);
    verify_refusals.push({ name, base: baseName, verifier: { fields: {}, signer_ik_sig_public_hex: keyHex, now_s }, signature_hex: b.signature_hex, expect: 'type_error' });
  };
  addVerifyRefusal('now_negative', 'reset', { now_s: -1 });
  addVerifyRefusal('now_fraction', 'reset', { now_s: 1.5 });
  addVerifyRefusal('now_2_pow_53', 'reset', { now_s: 9007199254740992 });
  addVerifyRefusal('acting_key_31_bytes', 'reset', { keyHex: A.ik_sig_public_hex.slice(0, 62), now_s: NOW });

  // ---- refusals ----
  const refusals = [];
  const addRefusal = (name, fields, expect) => {
    let got = 'built';
    try { buildMessage(fields); } catch (e) { if (!(e instanceof Refusal)) throw e; got = e.code; }
    if (got !== expect) throw new Error(`refusal ${name}: got ${got}, want ${expect}`);
    refusals.push({ name, fields, expect });
  };
  const ap = { action: 'approve', ...base, issued_at_s: NOW, target_device_id: T.device_id, target_ik_sig_pub_hex: T.ik_sig_public_hex };
  const rm = { action: 'remove', ...base, issued_at_s: NOW, target_device_id: T.device_id };
  const rs = { action: 'reset', ...base, issued_at_s: NOW };
  const without = (o, ...ks) => { const c = { ...o }; for (const k of ks) delete c[k]; return c; };

  addRefusal('uppercase_acting_id', { ...rs, acting_device_id: A.device_id.toUpperCase() }, 'invalid_device_id');
  addRefusal('uppercase_target_id', { ...ap, target_device_id: T.device_id.toUpperCase() }, 'invalid_device_id');
  addRefusal('uppercase_target_id_remove', { ...rm, target_device_id: T.device_id.toUpperCase() }, 'invalid_device_id');
  addRefusal('acting_id_without_hyphens', { ...rs, acting_device_id: A.device_id.replace(/-/g, '') }, 'invalid_device_id');
  addRefusal('acting_id_braced', { ...rs, acting_device_id: `{${A.device_id}}` }, 'invalid_device_id');
  addRefusal('session_id_uppercase', { ...rs, session_id: session.toUpperCase() }, 'type_error');
  addRefusal('session_id_not_uuid', { ...rs, session_id: 'not-a-session' }, 'type_error');
  addRefusal('unknown_action_Approve', { ...ap, action: 'Approve' }, 'type_error');
  addRefusal('unknown_action_sign_out_others', { ...rs, action: 'sign_out_others' }, 'type_error');
  addRefusal('approve_without_target_key', without(ap, 'target_ik_sig_pub_hex'), 'type_error');
  addRefusal('approve_target_key_31_bytes', { ...ap, target_ik_sig_pub_hex: T.ik_sig_public_hex.slice(0, 62) }, 'type_error');
  addRefusal('approve_target_key_33_bytes', { ...ap, target_ik_sig_pub_hex: T.ik_sig_public_hex + '00' }, 'type_error');
  addRefusal('approve_without_target_id', without(ap, 'target_device_id'), 'type_error');
  addRefusal('approve_of_acting_device', { ...ap, target_device_id: A.device_id, target_ik_sig_pub_hex: A.ik_sig_public_hex }, 'type_error');
  addRefusal('remove_with_target_key', { ...rm, target_ik_sig_pub_hex: T.ik_sig_public_hex }, 'type_error');
  addRefusal('remove_without_target_id', without(rm, 'target_device_id'), 'type_error');
  addRefusal('reset_with_target_id', { ...rs, target_device_id: T.device_id }, 'type_error');
  addRefusal('reset_with_target_key', { ...rs, target_ik_sig_pub_hex: T.ik_sig_public_hex }, 'type_error');
  addRefusal('refresh_with_target_key', { ...rs, action: 'refresh', target_ik_sig_pub_hex: T.ik_sig_public_hex }, 'type_error');
  addRefusal('refresh_with_target_id', { ...rs, action: 'refresh', target_device_id: T.device_id }, 'type_error');
  addRefusal('issued_at_negative', { ...rs, issued_at_s: -1 }, 'type_error');
  addRefusal('issued_at_fraction', { ...rs, issued_at_s: 1.5 }, 'type_error');
  addRefusal('issued_at_2_pow_53', { ...rs, issued_at_s: 9007199254740992 }, 'type_error');
  addRefusal('issued_at_string', { ...rs, issued_at_s: '1762560000' }, 'type_error');
  addRefusal('remove_empty_target_id', { ...rm, target_device_id: '' }, 'type_error');
  addRefusal('approve_empty_target_id', { ...ap, target_device_id: '' }, 'type_error');
  addRefusal('approve_empty_target_key', { ...ap, target_ik_sig_pub_hex: '' }, 'type_error');

  return {
    about: 'Device proof vectors, docs/SPEC.md §4.5: Ed25519 (RFC 8032) by the acting device\'s IKsig over the shortest-form CBOR array ["moretag/device-proof/v1", action, acting_device_id, session_id, issued_at_s, target_device_id, target_ik_sig_pub]. A field absent from `fields` goes on the wire as "" (text) or the empty byte string. In `verify`, `verifier.fields` overrides the base case\'s fields (null removes a field), `signer` names the party (or, for crafted keys, the key) whose IKsig public key, `signer_ik_sig_public_hex`, the verifier uses as the acting device\'s stored key, and `signature_hex` is the signature checked. `verify_refusals` are verifier inputs that throw (type_error). An empty target key is written target_ik_sig_pub_hex: "". Written independently by scripts/gen-vectors-device-v1.mjs from the spec and public texts only.',
    domain: PARAMS.proof_domain,
    params: PARAMS,
    parties: {
      ...parties,
      session_id: session,
      session_id_label: sessionLabel,
      other_session_id: otherSession,
      other_session_id_label: otherSessionLabel,
    },
    valid,
    verify,
    verify_refusals,
    refusals,
  };
}

function pairingCode(pub) {
  if (!(pub instanceof Uint8Array) || pub.length !== 32) throw new Refusal('type_error', 'IKsig must be 32 bytes');
  const d = sha256(Buffer.from(PARAMS.code_domain, 'utf8'), pub);
  const u = d.readUInt32BE(0);
  return { digest_prefix_hex: hex(d.subarray(0, 4)), uint32: u, code: String(u % 1000000).padStart(6, '0') };
}

function genCode() {
  const cases = [];
  const add = (name, extra, pub) => cases.push({ name, ...extra, ik_sig_public_hex: hex(pub), ...pairingCode(pub) });

  add('rfc8032_7_1_test1', { ik_sig_seed_hex: '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60' },
    unhex('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'));
  for (let i = 1; i <= 8; i++) {
    const label = `code/key/${i}`;
    const seed = secret(label);
    add(`ordinary_${i}`, { label, ik_sig_seed_hex: hex(seed) }, pubFromSeed(seed));
  }

  // Deterministic search over code/search/<n>, first match of each target.
  const want = { below_100000: null, below_1000: null, last_partial_block: null, collision: null };
  const seen = new Map();
  for (let n = 0; n < 2000000; n++) {
    const label = `code/search/${n}`;
    const seed = secret(label);
    const pub = pubFromSeed(seed);
    const c = pairingCode(pub);
    const rec = { label, seed, pub, c };
    const v = Number(c.code);
    if (!want.below_100000 && v < 100000 && v >= 1000) want.below_100000 = rec;
    if (!want.below_1000 && v < 1000) want.below_1000 = rec;
    if (!want.last_partial_block && c.uint32 >= 4294000000) want.last_partial_block = rec;
    if (!want.collision) {
      if (seen.has(c.code)) want.collision = [seen.get(c.code), rec]; else seen.set(c.code, rec);
    }
    if (Object.values(want).every(Boolean)) break;
  }
  if (!Object.values(want).every(Boolean)) throw new Error('search did not find every target');
  const addRec = (name, r, note) => add(name, { label: r.label, ik_sig_seed_hex: hex(r.seed), note }, r.pub);
  addRec('leading_zero_below_100000', want.below_100000, 'first code/search/<n> with a code in [1000, 100000)');
  addRec('below_1000', want.below_1000, 'first code/search/<n> with a code below 1000');
  addRec('last_partial_block', want.last_partial_block, 'first code/search/<n> with uint32 >= 4294000000 (the last, partial block of the modulo)');
  addRec('collision_a', want.collision[0], 'first pair of code/search/<n> keys with the same code (a)');
  addRec('collision_b', want.collision[1], 'first pair of code/search/<n> keys with the same code (b)');
  if (cases.at(-1).code !== cases.at(-2).code) throw new Error('collision broken');

  const refusals = [];
  const T = pubFromSeed(secret('code/key/1'));
  for (const [name, pub] of [['key_31_bytes', T.subarray(0, 31)], ['key_33_bytes', Buffer.concat([T, Buffer.from([0])])]]) {
    try { pairingCode(pub); throw new Error(`${name} accepted`); } catch (e) { if (!(e instanceof Refusal)) throw e; }
    refusals.push({ name, ik_sig_public_hex: hex(pub), expect: 'type_error' });
  }

  return {
    about: 'Pairing code vectors, docs/SPEC.md §4.5: code = uint32_be(SHA-256(UTF-8("moretag/device-code/v1") || IKsig)[0..4]) mod 10^6, written as six ASCII digits with leading zeros. digest_prefix_hex is the first 4 bytes of the SHA-256. Keys are Ed25519 public keys of the given seeds (seed = SHA-256(UTF-8("moretag-crypto/vectors/device/v1/" || label))). Written independently by scripts/gen-vectors-device-v1.mjs from the spec and public texts only.',
    domain: PARAMS.code_domain,
    cases,
    refusals,
  };
}

// ---------- main ----------

const mode = process.argv[2];
if (mode !== '--write' && mode !== '--check') {
  console.error('usage: gen-vectors-device-v1.mjs --write | --check');
  process.exit(2);
}
selfCheck();
const out = [
  [PROOF_FILE, JSON.stringify(genProof(), null, 2) + '\n'],
  [CODE_FILE, JSON.stringify(genCode(), null, 2) + '\n'],
];
if (mode === '--write') {
  for (const [f, s] of out) { fs.writeFileSync(f, s); console.log(`wrote: ${path.relative(process.cwd(), f)}`); }
} else {
  let bad = false;
  for (const [f, s] of out) {
    const disk = fs.existsSync(f) ? fs.readFileSync(f, 'utf8') : null;
    if (disk === s) console.log(`same: ${path.relative(process.cwd(), f)}`);
    else { bad = true; console.log(`DIFFERS: ${path.relative(process.cwd(), f)}`); }
  }
  process.exit(bad ? 1 : 0);
}

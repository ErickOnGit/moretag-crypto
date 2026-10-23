#!/usr/bin/env node
/**
 * gen-vectors-v2.mjs: independent known-answer vectors for moretag-crypto protocol v2.
 *
 * README
 *
 * What it computes. The published primitive vectors (RFC 7748, RFC 8032, RFC 5869,
 * draft-irtf-cfrg-xchacha-03), copied by hand below with their section numbers and checked
 * against Node's crypto and against hand-written second derivations (an RFC 7748 BigInt ladder,
 * an HMAC-built HKDF, a hand HChaCha20 and HChaCha20 recovered from OpenSSL's chacha20
 * keystream). Then protocol v2 as the design states it (X3DH with the 0xFF prefix, the 164-byte
 * AD, the Double Ratchet with the v2 KDF strings, XChaCha20-Poly1305 with AAD = AD || H, the CBOR
 * header array H with its grp slot, and the normative draw order): vectors/x3dh-v2.json,
 * vectors/ratchet-v2.json, vectors/aead-edges.json, vectors/spk-sig-msg-v1.json and
 * vectors/primitives.json. Every secret is SHA-256("moretag-crypto/vectors/v2/" || label) and the
 * label is stored beside it; the JSON is deterministic.
 *
 * What it never imports: anything but node:crypto, node:fs and node:path. No npm package and no
 * file of moretag-crypto. The author wrote it from supabase/drafts/crypto-v2/design.md (third
 * draft, 2026-10-22: §3.1 to §3.6 and §5) and the public texts only (X3DH revision 1, the Double
 * Ratchet in revision 1's numbering, RFC 7748, RFC 8032, RFC 5869, draft-irtf-cfrg-xchacha-03,
 * RFC 8949 for CBOR), and read no moretag-crypto source at any tag.
 *
 * libsignal. The --params mode runs the X3DH key derivation with another info string, output
 * length and split. On 2026-10-22 it was run once on the inputs and expected keys of
 * signalapp/libsignal tag v0.20.0 (commit ab29fed4db04a5335f8a0d1ea03b7a83b93776d2, before PQXDH),
 * rust/protocol/tests/ratchet.rs, tests test_ratcheting_session_as_bob and
 * test_ratcheting_session_as_alice (info "WhisperText", no salt, 64 bytes split 32 root / 32
 * chain), read from the source on the web; nothing was cloned or built, and the input file stayed
 * outside this repository. Outcome: the LIBSIGNAL_OUTCOME comment below. No libsignal constant is in this file
 * or in any vector file.
 *
 * Usage: node scripts/gen-vectors-v2.mjs --write | --check | --params <file.json>
 *   --write   self-check, then write vectors/*.json (nothing is written if the self-check fails)
 *   --check   self-check (the in-file transcription and vectors/primitives.json on disk), then
 *             regenerate every file in memory and compare it byte for byte with the file on disk
 *   --params  parameter mode: X3DH KDF with the info, length and split in the file (see runParams)
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

// LIBSIGNAL_OUTCOME: same: both tests reproduced (the responder side gives the expected sender
//   chain key and the initiator side the expected receiver chain key) for F, the DH1-DH3 pairings
//   and order, the absent salt (equal to 32 zero bytes), HKDF-SHA256 and a 64-byte output split
//   32/32; the same run without F matches neither. Not compared: DH4 (no one-time prekey in either
//   test) and the root step (neither test asserts a key from it).

const VECTORS_DIR = path.resolve(import.meta.dirname, '..', 'vectors');

// ---------------------------------------------------------------------------------------------
// The parameter object. Every constant cites the design line it implements; "readings" lists each
// byte-level choice the design leaves open, with the line it interprets.
// ---------------------------------------------------------------------------------------------

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

const PARAMS = Object.freeze({
  source: 'supabase/drafts/crypto-v2/design.md, third draft of 2026-10-22; "design.md:N" is line N of that file',
  labels: {
    prefix: 'moretag-crypto/vectors/v2/',
    rule: 'secret(label) = SHA-256(UTF-8(prefix || label)); a draw of n <= 32 bytes is the first n bytes of secret(label); longer data is secret(label + "/0") || secret(label + "/1") || ... cut to length',
    cite: 'design.md:384 (§5: secrets are SHA-256(moretag-crypto/vectors/v2/ || label), labels stored; JSON deterministic)',
  },
  x3dh: {
    curve: { value: 'X25519 and SHA-256', cite: 'design.md:135 (§3.1 item 1); X3DH rev 1 §2.1' },
    identity: { value: 'X25519 DH key IK plus a separate Ed25519 signing key IKsig', cite: 'design.md:136 (§3.1 item 2)' },
    spk_signature: {
      domain: 'moretag/x3dh/spk/v1',
      value: 'Ed25519 by IKsig over CBOR [domain, device_id (text string), IK (bstr 32), SPK (bstr 32), spk_id (uint)]',
      cite: 'design.md:137 (§3.1 item 3), design.md:95 (§2)',
    },
    f_hex: 'ff'.repeat(32),
    f_cite: 'design.md:138 (§3.1 item 4); X3DH rev 1 §2.2 ("32 0xFF bytes if curve is X25519")',
    dh_order: {
      value: 'DH1 = DH(IK_A, SPK_B), DH2 = DH(EK_A, IK_B), DH3 = DH(EK_A, SPK_B), DH4 = DH(EK_A, OPK_B) only when a one-time prekey was served; KM = F || DH1 || DH2 || DH3 [|| DH4], 128 or 160 bytes',
      cite: 'design.md:138 (§3.1 item 4); X3DH rev 1 §3.3',
    },
    kdf: {
      hash: 'sha256',
      f_hex: 'ff'.repeat(32),
      salt_hex: '00'.repeat(32),
      info_utf8: 'moretag/x3dh/v2',
      length: 32,
      split: [['sk', 32]],
      cite: 'design.md:139 (§3.1 item 5) and design.md:200 (§3.5); X3DH rev 1 §2.2 (salt = HashLen zero bytes, 32 bytes of output)',
    },
    all_zero_refused: { value: 'an all-zero DH output is refused, checked by OR-accumulating every byte', cite: 'design.md:140 (§3.1 item 6); RFC 7748 §6.1' },
    session_init: {
      value: 'v 2; sender_ik_sig_pub_b64 required; spk_id and opk_id integers 1 to 2^31 - 1; opk_id present exactly when used_opk',
      cite: 'design.md:141 (§3.1 item 7), design.md:205 (§3.5)',
    },
    initiator_order: { value: 'verify the SPK signature, then bundle.recipient_device_id == expected (device_mismatch), then DH', cite: 'design.md:143 (§3.1 item 9)' },
    self_session: { value: 'equal device ids throw self_session', cite: 'design.md:146 (§3.1 item 12)' },
  },
  ad: {
    ik_type_byte: 0x05,
    sig_type_byte: 0xed,
    length: 164,
    layout: '0x05 || IK_A (33), 0x05 || IK_B (33), 0xED || IKsig_A (33), 0xED || IKsig_B (33), dev_A (16 raw UUID bytes), dev_B (16); A is the initiator for the whole session',
    cite: 'design.md:150-160 (§3.2), design.md:162-163',
  },
  device_id: { regex: UUID_RE.source, cite: 'design.md:164 (§3.2: canonical lowercase UUID strings; anything else is invalid_device_id)' },
  ratchet: {
    init_initiator: { value: 'fresh DHs; DHr = SPK_B; RK, CKs = KDF_RK(SK, DH(DHs, SPK_B))', cite: 'design.md:170 (§3.3 item 1); DR §3.3 RatchetInitAlice' },
    init_responder: { value: 'DHs = a copy of the SPK pair; no DHr; RK = SK; no chains', cite: 'design.md:171 (§3.3 item 2); DR §3.3 RatchetInitBob' },
    kdf_rk: {
      hash: 'sha256', salt: 'rk', ikm: 'dh_out', info_utf8: 'moretag/v2/rkck', length: 64, split: [['root_key', 32], ['chain_key', 32]],
      cite: 'design.md:172 (§3.3 item 3); DR §3.1 (KDF_RK returns a pair (32-byte root key, 32-byte chain key)), DR §5.2',
    },
    kdf_ck: {
      hash: 'sha256', salt_hex: '', ikm: 'ck', info_utf8: 'moretag/v2/ckmk', length: 64, split: [['chain_key', 32], ['message_key', 32]],
      cite: 'design.md:173 (§3.3 item 4); DR §3.1 (KDF_CK returns a pair (32-byte chain key, 32-byte message key))',
    },
    aead: { value: 'XChaCha20-Poly1305 under mk, a random 24-byte nonce carried in the header, the 16-byte tag appended', cite: 'design.md:174 (§3.3 item 5); draft-irtf-cfrg-xchacha-03 §2.3' },
    aad: { value: 'AD (164 bytes) || H', cite: 'design.md:175 (§3.3 item 6); DR §3.1 CONCAT(ad, header)' },
    header_ids: { value: 'encrypt writes the ids from AD by role; decrypt refuses ids that differ from AD before any AEAD (device_mismatch)', cite: 'design.md:176 (§3.3 item 7)' },
    max_skip: 1000,
    skipped_cache: 2000,
    skip_cite: 'design.md:177 (§3.3 item 8); DR §3.5 MAX_SKIP',
    replay: { value: 'replay_detected on the current receiving chain when n < nr and no skipped key exists, before authentication; an earlier-chain replay fails the AEAD (decrypt_failed)', cite: 'design.md:178 (§3.3 item 9)' },
    no_sending_chain: { value: 'encrypt without CKs throws no_sending_chain', cite: 'design.md:180 (§3.3 item 11)' },
    decrypt_order: { value: 'v === 2, header ids against AD, skipped key, replay check, skip, DH step (one 32-byte draw), AEAD', cite: 'pr-briefs.md L2 scope (ratchetDecrypt); design.md:176-178' },
  },
  header: {
    alg: 'xchacha20poly1305',
    h: '[2, "xchacha20poly1305", nonce (bstr 24), dev_sender (bstr 16), dev_recipient (bstr 16), dh_pub (bstr 32), pn (uint), n (uint), grp]; grp = null | [gid (bstr 16), epoch (uint)]; shortest-form CBOR, no tags',
    cite: 'design.md:184-190 (§3.4), design.md:194 (grp: gid a canonical UUID, epoch a safe integer >= 0)',
  },
  draws: {
    order: [
      'x3dhInitiatorBootstrapV2: EK private (32), then DHs private (32)',
      'x3dhResponderBootstrapV2, ratchetInitResponderV2: none',
      'ratchetEncrypt: one 24-byte nonce',
      'ratchetDecrypt when dh_pub differs from DHr or DHr is absent: one 32-byte DHs private, after the old chain is skipped and the receiving chain stepped; none otherwise',
      'sealLocalV2: one 24-byte nonce',
    ],
    cite: 'design.md:216-221 (§3.6)',
  },
  self_seal: { aad: 'CBOR ["moretag/self/v1", device_id (text string)]', header: '{ v: 2, kind: "self", nonce }', cite: 'design.md:234 (§3.8)' },
  aead_edges: {
    plaintext_lengths: [0, 1, 15, 16, 17, 63, 64, 65, 16500],
    aad_lengths: [0, 1, 16, 17],
    cite: 'design.md:388 (§5)',
  },
  readings: [
    { topic: 'KDF_RK split', reading: 'first 32 bytes = new root key, last 32 = chain key', interprets: 'design.md:172 ("split 32/32"), ordered as DR §3.1 returns the pair' },
    { topic: 'KDF_CK split', reading: 'first 32 bytes = next chain key, last 32 = message key', interprets: 'design.md:173 ("split 32/32", info "ckmk"), ordered as DR §3.1 returns the pair' },
    { topic: 'KDF_CK salt', reading: 'a zero-length salt (RFC 5869 §2.2 makes it equal to 32 zero bytes; primitives.json proves the equality)', interprets: 'design.md:173 ("salt = empty")' },
    { topic: 'X25519 private keys', reading: 'stored and serialized as the raw 32-byte draw, not clamped; X25519 clamps inside (RFC 7748 §5)', interprets: 'design.md:208 (dh_self.priv32_b64), design.md:216-219 (32-byte draws)' },
    { topic: 'device id inside signed or self-seal CBOR', reading: 'the canonical UUID text string (major type 3); in AD and H it is the 16 raw bytes', interprets: 'design.md:137 (unchanged v1 message, where ids were strings), design.md:234 (["moretag/self/v1", device_id]); design.md:157-158 and :187 for raw bytes' },
    { topic: '24-byte and long draws', reading: 'a 24-byte draw is the first 24 bytes of secret(label); data longer than 32 bytes concatenates secret(label + "/" + i)', interprets: 'design.md:384 (secrets defined only as one SHA-256)' },
    { topic: 'vector device ids', reading: 'the first 16 bytes of secret(label) with the version-4 and RFC 4122 variant bits set; "canonical" checks only lowercase 8-4-4-4-12 hex, not the version bits', interprets: 'design.md:164' },
    { topic: 'header ids', reading: 'the encryptor writes dev_sender = its own id and dev_recipient = the peer id, both read from AD by role; decrypt requires dev_sender = the peer id and dev_recipient = its own id', interprets: 'design.md:176' },
    { topic: 'replay check position', reading: 'a skipped key for (dh_pub, n) is looked up first; only without one does n < nr on the current chain give replay_detected', interprets: 'design.md:178 ("and no skipped key exists")' },
    { topic: 'wire JSON names', reading: 'only the bytes that enter a KDF, a signature or an AEAD are normative here; JSON field names other than those the design names (v, sender_ik_sig_pub_b64, spk_id, opk_id, used_opk, opk_pub_b64, recipient_device_id, grp {gid, epoch}, kind, nonce) are this generator\'s', interprets: 'design.md:205-206 (§3.5 table), design.md:184' },
    { topic: 'pairwise grp on the wire', reading: 'the grp key is absent from the wire header of a pairwise message; H carries null', interprets: 'design.md:189, design.md:194 ("Pairwise messages carry null"), pr-briefs L2 ("optional grp")' },
    { topic: 'serialized state', reading: 'role is "initiator" or "responder"; skipped is an array of {dh_pub32_b64, n, mk32_b64} in insertion order (oldest first)', interprets: 'design.md:208 (skipped has no stated layout)' },
    { topic: 'base64', reading: 'standard alphabet with padding, canonical (decode then encode gives the same text)', interprets: 'design.md:72 ("strict canonical base64"), design.md:208' },
    { topic: 'refusal codes the design does not name', reading: 'expected_code null means "refused with any typed error"; used for an all-zero DH output, a malformed grp, a bad bundle signature and session_init shape errors', interprets: 'design.md:398 (the code list), design.md:388' },
    { topic: 'sidecar sender differing from the row', reading: 'device_mismatch', interprets: 'design.md:107 and pr-briefs L2 ("refuses a differing sidecar id", no code named)' },
    { topic: 'aead-edges pairing', reading: 'every plaintext length up to 65 with every AAD length (32 cases); 16,500 with AAD length 17 only, to keep the file small', interprets: 'design.md:388 (lists lengths, not their pairing)' },
    { topic: 'self-seal header field', reading: 'the header field is named nonce (base64), as the design writes it; the header is not in the AAD', interprets: 'design.md:234' },
    { topic: 'Double Ratchet revision', reading: 'signal.org now serves revision 4 (2025-11-04), whose classical sections 3.1-3.5 give the pseudocode used here; revision 1 numbering is kept in citations (revision 4 moved "recommended cryptographic algorithms" from §5.2 to §7.2)', interprets: 'design.md:9' },
  ],
});

// ---------------------------------------------------------------------------------------------
// Bytes, labels, errors
// ---------------------------------------------------------------------------------------------

const utf8 = (s) => Buffer.from(s, 'utf8');
const hex = (b) => Buffer.from(b).toString('hex');
const b64 = (b) => Buffer.from(b).toString('base64');
const cat = (...parts) => Buffer.concat(parts.map((p) => Buffer.from(p)));
const sha256 = (...parts) => crypto.createHash('sha256').update(cat(...parts)).digest();

function unhex(s) {
  if (typeof s !== 'string' || !/^([0-9a-f]{2})*$/.test(s)) throw new Error(`not lowercase hex: ${String(s).slice(0, 20)}`);
  return Buffer.from(s, 'hex');
}

function fail(message) {
  throw new Error(message);
}

function assertBytes(actual, expected, what) {
  if (!Buffer.from(actual).equals(Buffer.from(expected))) fail(`${what}: got ${hex(actual)}, expected ${hex(expected)}`);
}

class ProtoError extends Error {
  constructor(code, reason) {
    super(reason ?? code);
    this.code = code;
  }
}

const secret = (label) => sha256(utf8(PARAMS.labels.prefix + label));

function labelledBytes(label, length) {
  if (length <= 32) return Buffer.from(secret(label).subarray(0, length));
  const blocks = [];
  for (let i = 0; blocks.length * 32 < length; i++) blocks.push(secret(`${label}/${i}`));
  return Buffer.from(cat(...blocks).subarray(0, length));
}

function uuidFromBytes(b) {
  const h = hex(b);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20, 32)}`;
}

function labelledUuid(label) {
  const b = Buffer.from(secret(label).subarray(0, 16));
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  return uuidFromBytes(b);
}

function canonicalId(s) {
  if (typeof s !== 'string' || !UUID_RE.test(s)) throw new ProtoError('invalid_device_id');
  return s;
}

const uuidBytes = (s) => unhex(canonicalId(s).replaceAll('-', ''));

function strictB64(s, length, code) {
  if (typeof s !== 'string' || !/^[A-Za-z0-9+/]*={0,2}$/.test(s)) throw new ProtoError(code, 'not base64');
  const b = Buffer.from(s, 'base64');
  if (b64(b) !== s) throw new ProtoError(code, 'non-canonical base64');
  if (length !== undefined && b.length !== length) throw new ProtoError(code, `length ${b.length}, expected ${length}`);
  return b;
}

// ---------------------------------------------------------------------------------------------
// CBOR, shortest form (RFC 8949 §4.2.1), only the types the design uses
// ---------------------------------------------------------------------------------------------

function cborHead(major, value) {
  const n = BigInt(value);
  if (n < 0n) fail('CBOR: negative argument');
  if (n < 24n) return Buffer.from([(major << 5) | Number(n)]);
  if (n < 0x100n) return Buffer.from([(major << 5) | 24, Number(n)]);
  if (n < 0x10000n) {
    const b = Buffer.alloc(3);
    b[0] = (major << 5) | 25;
    b.writeUInt16BE(Number(n), 1);
    return b;
  }
  if (n < 0x100000000n) {
    const b = Buffer.alloc(5);
    b[0] = (major << 5) | 26;
    b.writeUInt32BE(Number(n), 1);
    return b;
  }
  if (n < 1n << 64n) {
    const b = Buffer.alloc(9);
    b[0] = (major << 5) | 27;
    b.writeBigUInt64BE(n, 1);
    return b;
  }
  fail('CBOR: argument too large');
}

function cbor(v) {
  if (v === null) return Buffer.from([0xf6]);
  if (typeof v === 'bigint') return cborHead(0, v);
  if (typeof v === 'number') {
    if (!Number.isSafeInteger(v) || v < 0) fail('CBOR: only unsigned safe integers are encoded');
    return cborHead(0, v);
  }
  if (typeof v === 'string') {
    const b = utf8(v);
    return cat(cborHead(3, b.length), b);
  }
  if (v instanceof Uint8Array) return cat(cborHead(2, v.length), v);
  if (Array.isArray(v)) return cat(cborHead(4, v.length), ...v.map(cbor));
  fail('CBOR: unsupported value');
}

// RFC 8949 Appendix A, Table 6 rows (copied by hand), for the encoder's own self-test.
const CBOR_RFC8949_APPENDIX_A = [
  [0, '00'], [23, '17'], [24, '1818'], [25, '1819'], [100, '1864'], [1000, '1903e8'],
  [1000000, '1a000f4240'], [1000000000000, '1b000000e8d4a51000'], [18446744073709551615n, '1bffffffffffffffff'],
  [null, 'f6'], [Buffer.alloc(0), '40'], [Buffer.from([1, 2, 3, 4]), '4401020304'],
  ['', '60'], ['a', '6161'], ['IETF', '6449455446'], ['ü', '62c3bc'],
  [[], '80'], [[1, 2, 3], '83010203'], [[1, [2, 3], [4, 5]], '8301820203820405'],
  [Array.from({ length: 25 }, (_, i) => i + 1), '98190102030405060708090a0b0c0d0e0f101112131415161718181819'],
];

// ---------------------------------------------------------------------------------------------
// X25519 (raw DER into node:crypto) and the RFC 7748 §5 ladder as a second derivation
// ---------------------------------------------------------------------------------------------

const DER = {
  x25519Pkcs8: unhex('302e020100300506032b656e04220420'),
  x25519Spki: unhex('302a300506032b656e032100'),
  ed25519Pkcs8: unhex('302e020100300506032b657004220420'),
  ed25519Spki: unhex('302a300506032b6570032100'),
};

function need(b, length, what) {
  if (!(b instanceof Uint8Array) || b.length !== length) fail(`${what}: expected ${length} bytes`);
  return Buffer.from(b);
}

const x25519PrivateKey = (priv) => crypto.createPrivateKey({ key: cat(DER.x25519Pkcs8, need(priv, 32, 'X25519 private')), format: 'der', type: 'pkcs8' });
const x25519PublicKey = (pub) => crypto.createPublicKey({ key: cat(DER.x25519Spki, need(pub, 32, 'X25519 public')), format: 'der', type: 'spki' });

const P = 2n ** 255n - 19n;
const A24 = 121665n;
const modp = (a) => ((a % P) + P) % P;

function powmod(base, exp) {
  let r = 1n;
  let b = modp(base);
  let e = exp;
  while (e > 0n) {
    if (e & 1n) r = (r * b) % P;
    b = (b * b) % P;
    e >>= 1n;
  }
  return r;
}

function leToBig(b) {
  let n = 0n;
  for (let i = b.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(b[i]);
  return n;
}

function bigToLe(n, length) {
  const out = Buffer.alloc(length);
  let v = n;
  for (let i = 0; i < length; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  if (v !== 0n) fail('bigToLe overflow');
  return out;
}

// RFC 7748 §5: decodeScalar25519, decodeUCoordinate (top bit masked, non-canonical values reduced),
// the Montgomery ladder with a24 = 121665, and x_2 * z_2^(p - 2).
function x25519Ladder(k32, u32) {
  const kb = need(k32, 32, 'ladder scalar');
  kb[0] &= 248;
  kb[31] &= 127;
  kb[31] |= 64;
  const k = leToBig(kb);
  const ub = need(u32, 32, 'ladder u');
  ub[31] &= 127;
  const x1 = modp(leToBig(ub));
  let x2 = 1n;
  let z2 = 0n;
  let x3 = x1;
  let z3 = 1n;
  let swap = 0n;
  for (let t = 254n; t >= 0n; t--) {
    const kt = (k >> t) & 1n;
    swap ^= kt;
    if (swap) {
      [x2, x3] = [x3, x2];
      [z2, z3] = [z3, z2];
    }
    swap = kt;
    const A = modp(x2 + z2);
    const AA = (A * A) % P;
    const B = modp(x2 - z2);
    const BB = (B * B) % P;
    const E = modp(AA - BB);
    const C = modp(x3 + z3);
    const D = modp(x3 - z3);
    const DA = (D * A) % P;
    const CB = (C * B) % P;
    x3 = modp((DA + CB) * (DA + CB));
    z3 = modp(x1 * modp((DA - CB) * (DA - CB)));
    x2 = (AA * BB) % P;
    z2 = modp(E * modp(AA + A24 * E));
  }
  if (swap) {
    [x2, x3] = [x3, x2];
    [z2, z3] = [z3, z2];
  }
  return bigToLe(modp(x2 * powmod(z2, P - 2n)), 32);
}

function isAllZero(b) {
  let acc = 0;
  for (const x of b) acc |= x;
  return acc === 0;
}

function x25519Public(priv) {
  const der = crypto.createPublicKey(x25519PrivateKey(priv)).export({ format: 'der', type: 'spki' });
  assertBytes(der.subarray(0, 12), DER.x25519Spki, 'X25519 SPKI prefix');
  const pub = Buffer.from(der.subarray(12));
  assertBytes(pub, x25519Ladder(priv, bigToLe(9n, 32)), 'X25519 public key: node:crypto against the ladder');
  return pub;
}

// One X25519 agreement. node:crypto (OpenSSL) refuses an all-zero result itself; the explicit
// OR-accumulate check stays, and every result is recomputed with the ladder.
function dh(priv, pub) {
  let out;
  try {
    out = crypto.diffieHellman({ privateKey: x25519PrivateKey(priv), publicKey: x25519PublicKey(pub) });
  } catch (e) {
    if (e && e.code === 'ERR_OSSL_FAILED_DURING_DERIVATION') throw new ProtoError('low_order', 'all-zero X25519 output');
    throw e;
  }
  if (isAllZero(out)) throw new ProtoError('low_order', 'all-zero X25519 output');
  assertBytes(out, x25519Ladder(priv, pub), 'X25519: node:crypto against the ladder');
  return Buffer.from(out);
}

// ---------------------------------------------------------------------------------------------
// Ed25519 (raw DER into node:crypto)
// ---------------------------------------------------------------------------------------------

const ed25519PrivateKey = (seed) => crypto.createPrivateKey({ key: cat(DER.ed25519Pkcs8, need(seed, 32, 'Ed25519 seed')), format: 'der', type: 'pkcs8' });

function ed25519Public(seed) {
  const der = crypto.createPublicKey(ed25519PrivateKey(seed)).export({ format: 'der', type: 'spki' });
  assertBytes(der.subarray(0, 12), DER.ed25519Spki, 'Ed25519 SPKI prefix');
  return Buffer.from(der.subarray(12));
}

const ed25519Sign = (seed, message) => Buffer.from(crypto.sign(null, Buffer.from(message), ed25519PrivateKey(seed)));

function ed25519Verify(pub, message, signature) {
  const key = crypto.createPublicKey({ key: cat(DER.ed25519Spki, need(pub, 32, 'Ed25519 public')), format: 'der', type: 'spki' });
  return crypto.verify(null, Buffer.from(message), key, Buffer.from(signature));
}

// RFC 8032 §5.1: L = 2^252 + 27742317777372353535851937790883648493
const ED25519_L = 2n ** 252n + 27742317777372353535851937790883648493n;

// ---------------------------------------------------------------------------------------------
// HKDF-SHA256: node:crypto hkdfSync, checked on every call against an HMAC-built RFC 5869 §2.2-2.3
// ---------------------------------------------------------------------------------------------

function hkdfByHmac(ikm, salt, info, length) {
  const prk = crypto.createHmac('sha256', Buffer.from(salt)).update(Buffer.from(ikm)).digest();
  const blocks = [];
  let t = Buffer.alloc(0);
  for (let i = 1; blocks.length * 32 < length; i++) {
    t = crypto.createHmac('sha256', prk).update(cat(t, info, [i])).digest();
    blocks.push(t);
  }
  return { prk, okm: Buffer.from(cat(...blocks).subarray(0, length)) };
}

function hkdf(ikm, salt, info, length) {
  const okm = Buffer.from(crypto.hkdfSync('sha256', Buffer.from(ikm), Buffer.from(salt), Buffer.from(info), length));
  assertBytes(okm, hkdfByHmac(ikm, salt, info, length).okm, 'HKDF: hkdfSync against the HMAC construction');
  return okm;
}

// ---------------------------------------------------------------------------------------------
// HChaCha20 (draft-irtf-cfrg-xchacha-03 §2.2) by hand and from OpenSSL's chacha20 keystream;
// XChaCha20-Poly1305 per §2.3 with Node's IETF chacha20-poly1305
// ---------------------------------------------------------------------------------------------

const rotl = (x, n) => ((x << n) | (x >>> (32 - n))) >>> 0;

function quarterRound(s, a, b, c, d) {
  s[a] += s[b]; s[d] = rotl(s[d] ^ s[a], 16);
  s[c] += s[d]; s[b] = rotl(s[b] ^ s[c], 12);
  s[a] += s[b]; s[d] = rotl(s[d] ^ s[a], 8);
  s[c] += s[d]; s[b] = rotl(s[b] ^ s[c], 7);
}

// Words 0-3 the constants "expand 32-byte k", 4-11 the key, 12-15 the 16 nonce bytes (the first
// 32 bits of the nonce take the block counter's place, §2.2), all little-endian.
function chachaState(key, nonce16) {
  const s = new Uint32Array(16);
  s[0] = 0x61707865; s[1] = 0x3320646e; s[2] = 0x79622d32; s[3] = 0x6b206574;
  for (let i = 0; i < 8; i++) s[4 + i] = key.readUInt32LE(4 * i);
  for (let i = 0; i < 4; i++) s[12 + i] = nonce16.readUInt32LE(4 * i);
  return s;
}

function hchacha20ByHand(key, nonce16) {
  const s = chachaState(need(key, 32, 'HChaCha20 key'), need(nonce16, 16, 'HChaCha20 nonce'));
  for (let i = 0; i < 10; i++) {
    quarterRound(s, 0, 4, 8, 12); quarterRound(s, 1, 5, 9, 13); quarterRound(s, 2, 6, 10, 14); quarterRound(s, 3, 7, 11, 15);
    quarterRound(s, 0, 5, 10, 15); quarterRound(s, 1, 6, 11, 12); quarterRound(s, 2, 7, 8, 13); quarterRound(s, 3, 4, 9, 14);
  }
  const out = Buffer.alloc(32);
  for (let i = 0; i < 4; i++) {
    out.writeUInt32LE(s[i], 4 * i);
    out.writeUInt32LE(s[12 + i], 16 + 4 * i);
  }
  return out;
}

// OpenSSL's chacha20 takes a 16-byte IV: a 32-bit little-endian counter then a 96-bit nonce, which
// is exactly words 12-15. One keystream block is rounds(state) + state, so subtracting the input
// state word by word leaves the 20-round output that HChaCha20 returns words 0-3 and 12-15 of.
function hchacha20FromOpenSsl(key, nonce16) {
  const k = need(key, 32, 'HChaCha20 key');
  const n = need(nonce16, 16, 'HChaCha20 nonce');
  const cipher = crypto.createCipheriv('chacha20', k, n);
  const block = cat(cipher.update(Buffer.alloc(64)), cipher.final());
  const init = chachaState(k, n);
  const out = Buffer.alloc(32);
  const word = (i) => (block.readUInt32LE(4 * i) - init[i]) >>> 0;
  for (let i = 0; i < 4; i++) {
    out.writeUInt32LE(word(i), 4 * i);
    out.writeUInt32LE(word(12 + i), 16 + 4 * i);
  }
  return out;
}

function hchacha20(key, nonce16) {
  const a = hchacha20ByHand(key, nonce16);
  assertBytes(a, hchacha20FromOpenSsl(key, nonce16), 'HChaCha20: hand against OpenSSL keystream');
  return a;
}

function xchachaParts(key, nonce24) {
  const n = need(nonce24, 24, 'XChaCha20 nonce');
  return { subkey: hchacha20(key, n.subarray(0, 16)), nonce12: cat(Buffer.alloc(4), n.subarray(16, 24)) };
}

function xchachaSeal(key, nonce24, aad, plaintext) {
  const { subkey, nonce12 } = xchachaParts(key, nonce24);
  const c = crypto.createCipheriv('chacha20-poly1305', subkey, nonce12, { authTagLength: 16 });
  c.setAAD(Buffer.from(aad), { plaintextLength: plaintext.length });
  const ct = cat(c.update(Buffer.from(plaintext)), c.final());
  return cat(ct, c.getAuthTag());
}

function xchachaOpen(key, nonce24, aad, sealed) {
  if (sealed.length < 16) throw new ProtoError('decrypt_failed', 'shorter than a tag');
  const { subkey, nonce12 } = xchachaParts(key, nonce24);
  const d = crypto.createDecipheriv('chacha20-poly1305', subkey, nonce12, { authTagLength: 16 });
  d.setAAD(Buffer.from(aad), { plaintextLength: sealed.length - 16 });
  d.setAuthTag(Buffer.from(sealed.subarray(sealed.length - 16)));
  try {
    return cat(d.update(Buffer.from(sealed.subarray(0, sealed.length - 16))), d.final());
  } catch {
    throw new ProtoError('decrypt_failed', 'AEAD authentication failed');
  }
}

// ---------------------------------------------------------------------------------------------
// The published primitive vectors, copied by hand. Hex lines are kept as the documents print them.
// ---------------------------------------------------------------------------------------------

const j = (...lines) => lines.join('');

const PUBLISHED = {
  x25519: {
    rfc7748_5_2_vector_1: {
      source: 'RFC 7748 §5.2, first X25519 test vector',
      scalar: 'a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4',
      u: 'e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c',
      output: 'c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552',
    },
    rfc7748_5_2_vector_2: {
      source: 'RFC 7748 §5.2, second X25519 test vector',
      scalar: '4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d',
      u: 'e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493',
      output: '95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957',
    },
    rfc7748_5_2_iterated: {
      source: 'RFC 7748 §5.2, X25519 iterated from k = u = 9; each round k, u = X25519(k, u), k',
      start: '0900000000000000000000000000000000000000000000000000000000000000',
      after_1: '422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079',
      after_1000: '684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51',
    },
    rfc7748_6_1: {
      source: 'RFC 7748 §6.1, Curve25519 Diffie-Hellman',
      alice_private: '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a',
      alice_public: '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a',
      bob_private: '5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb',
      bob_public: 'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f',
      shared: '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742',
    },
    derived_low_order_refused: {
      source: 'derived, not published: u-coordinates of points whose order divides 8 (0, 1, p - 1 and the two order-8 points) and the non-canonical encodings p and p + 1; each gives the all-zero output for every clamped scalar (checked with the ladder) and is refused (RFC 7748 §6.1 all-zero check)',
      values: [
        { name: 'zero', u: '0000000000000000000000000000000000000000000000000000000000000000' },
        { name: 'one', u: '0100000000000000000000000000000000000000000000000000000000000000' },
        { name: 'order_8_a', u: 'e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800' },
        { name: 'order_8_b', u: '5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157' },
        { name: 'p_minus_1', u: 'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f' },
        { name: 'p', u: 'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f' },
        { name: 'p_plus_1', u: 'eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f' },
      ],
    },
  },
  ed25519: {
    rfc8032_7_1_test_1: {
      source: 'RFC 8032 §7.1, TEST 1',
      secret_key: j('9d61b19deffd5a60ba844af492ec2cc4', '4449c5697b326919703bac031cae7f60'),
      public_key: j('d75a980182b10ab7d54bfed3c964073a', '0ee172f3daa62325af021a68f707511a'),
      message: '',
      signature: j('e5564300c360ac729086e2cc806e828a', '84877f1eb8e5d974d873e06522490155', '5fb8821590a33bacc61e39701cf9b46b', 'd25bf5f0595bbe24655141438e7a100b'),
    },
    rfc8032_7_1_test_2: {
      source: 'RFC 8032 §7.1, TEST 2',
      secret_key: j('4ccd089b28ff96da9db6c346ec114e0f', '5b8a319f35aba624da8cf6ed4fb8a6fb'),
      public_key: j('3d4017c3e843895a92b70aa74d1b7ebc', '9c982ccf2ec4968cc0cd55f12af4660c'),
      message: '72',
      signature: j('92a009a9f0d4cab8720e820b5f642540', 'a2b27b5416503f8fb3762223ebdb69da', '085ac1e43e15996e458f3613d0f11d8c', '387b2eaeb4302aeeb00d291612bb0c00'),
    },
    rfc8032_7_1_test_3: {
      source: 'RFC 8032 §7.1, TEST 3',
      secret_key: j('c5aa8df43f9f837bedb7442f31dcb7b1', '66d38535076f094b85ce3a2e0b4458f7'),
      public_key: j('fc51cd8e6218a1a38da47ed00230f058', '0816ed13ba3303ac5deb911548908025'),
      message: 'af82',
      signature: j('6291d657deec24024827e69c3abe01a3', '0ce548a284743a445e3680d7db5ac3ac', '18ff9b538d16f290ae67f760984dc659', '4a7c15e9716ed28dc027beceea1ec40a'),
    },
  },
  hkdf_sha256: {
    rfc5869_a_1: {
      source: 'RFC 5869 Appendix A.1 (Test Case 1)',
      ikm: '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b',
      salt: '000102030405060708090a0b0c',
      info: 'f0f1f2f3f4f5f6f7f8f9',
      length: 42,
      prk: j('077709362c2e32df0ddc3f0dc47bba63', '90b6c73bb50f9c3122ec844ad7c2b3e5'),
      okm: j('3cb25f25faacd57a90434f64d0362f2a', '2d2d0a90cf1a5a4c5db02d56ecc4c5bf', '34007208d5b887185865'),
    },
    rfc5869_a_2: {
      source: 'RFC 5869 Appendix A.2 (Test Case 2)',
      ikm: j('000102030405060708090a0b0c0d0e0f', '101112131415161718191a1b1c1d1e1f', '202122232425262728292a2b2c2d2e2f', '303132333435363738393a3b3c3d3e3f', '404142434445464748494a4b4c4d4e4f'),
      salt: j('606162636465666768696a6b6c6d6e6f', '707172737475767778797a7b7c7d7e7f', '808182838485868788898a8b8c8d8e8f', '909192939495969798999a9b9c9d9e9f', 'a0a1a2a3a4a5a6a7a8a9aaabacadaeaf'),
      info: j('b0b1b2b3b4b5b6b7b8b9babbbcbdbebf', 'c0c1c2c3c4c5c6c7c8c9cacbcccdcecf', 'd0d1d2d3d4d5d6d7d8d9dadbdcdddedf', 'e0e1e2e3e4e5e6e7e8e9eaebecedeeef', 'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'),
      length: 82,
      prk: j('06a6b88c5853361a06104c9ceb35b45c', 'ef760014904671014a193f40c15fc244'),
      okm: j('b11e398dc80327a1c8e7f78c596a4934', '4f012eda2d4efad8a050cc4c19afa97c', '59045a99cac7827271cb41c65e590e09', 'da3275600c2f09b8367793a9aca3db71', 'cc30c58179ec3e87c14c01d5c1f3434f', '1d87'),
    },
    rfc5869_a_3: {
      source: 'RFC 5869 Appendix A.3 (Test Case 3: zero-length salt and info)',
      ikm: '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b',
      salt: '',
      info: '',
      length: 42,
      prk: j('19ef24a32c717b167f33a91d6f648bdf', '96596776afdb6377ac434c1c293ccb04'),
      okm: j('8da4e775a563c18f715f802a063c5a31', 'b8a11f5c5ee1879ec3454e5f3c738d2d', '9d201395faa4b61a96c8'),
    },
  },
  hchacha20: {
    draft_xchacha_03_2_2_1: {
      source: 'draft-irtf-cfrg-xchacha-03 §2.2.1 (colon-separated bytes and spaced words joined)',
      key: '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
      nonce: '000000090000004a0000000031415927',
      output: j('82413b42', '27b27bfe', 'd30e4250', '8a877d73', 'a0f9e4d5', '8a74a853', 'c12ec413', '26d3ecdc'),
    },
  },
  xchacha20poly1305: {
    draft_xchacha_03_a_3_1: {
      source: 'draft-irtf-cfrg-xchacha-03 Appendix A.3.1 (AEAD_XChaCha20_Poly1305); the 114-byte plaintext is not reproduced: decrypting with the published tag recovers it, and plaintext_sha256 (derived) pins it',
      key: '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f',
      nonce: '404142434445464748494a4b4c4d4e4f5051525354555657',
      aad: '50515253c0c1c2c3c4c5c6c7',
      plaintext_length: 114,
      ciphertext: j(
        'bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb',
        '731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452',
        '2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9',
        '21f9664c97637da9768812f615c68b13b52e',
      ),
      tag: 'c0875924c1c7987947deafd8780acf49',
    },
  },
};

// The derived entries that primitives.json adds to the transcription.
function buildPrimitivesObject() {
  const t1 = PUBLISHED.ed25519.rfc8032_7_1_test_1;
  const sig = unhex(t1.signature);
  const sPlusL = leToBig(sig.subarray(32)) + ED25519_L;
  const a1 = PUBLISHED.hkdf_sha256.rfc5869_a_1;
  const a3 = PUBLISHED.hkdf_sha256.rfc5869_a_3;
  const ax = PUBLISHED.xchacha20poly1305.draft_xchacha_03_a_3_1;
  const pt = xchachaOpen(unhex(ax.key), unhex(ax.nonce), unhex(ax.aad), unhex(ax.ciphertext + ax.tag));
  return {
    about: 'Published primitive vectors, copied by hand from the cited sections, and derived entries (marked derived). Generated by scripts/gen-vectors-v2.mjs; every value is checked against node:crypto and a hand-written second derivation before any file is written.',
    x25519: PUBLISHED.x25519,
    ed25519: {
      ...PUBLISHED.ed25519,
      derived_test_1_s_plus_l_refused: {
        source: 'derived from RFC 8032 §7.1 TEST 1: S replaced by S + L (L = 2^252 + 27742317777372353535851937790883648493, RFC 8032 §5.1); RFC 8032 §5.1.7 requires 0 <= S < L, so verification must fail',
        public_key: t1.public_key,
        message: t1.message,
        signature: hex(cat(sig.subarray(0, 32), bigToLe(sPlusL, 32))),
        valid: false,
      },
    },
    hkdf_sha256: {
      ...PUBLISHED.hkdf_sha256,
      derived_length_32_prefix: {
        source: 'derived from RFC 5869 A.1: the same inputs with L = 32 give the first 32 bytes of the 42-byte OKM',
        ikm: a1.ikm,
        salt: a1.salt,
        info: a1.info,
        length: 32,
        okm: a1.okm.slice(0, 64),
      },
      derived_empty_salt_equals_zero_salt: {
        source: 'derived from RFC 5869 A.3 and §2.2 ("if not provided, it is set to a string of HashLen zeros"): A.3 recomputed with salt = 32 zero bytes gives the same PRK and OKM',
        ikm: a3.ikm,
        salt: '00'.repeat(32),
        info: a3.info,
        length: a3.length,
        prk: a3.prk,
        okm: a3.okm,
      },
    },
    hchacha20: PUBLISHED.hchacha20,
    xchacha20poly1305: {
      draft_xchacha_03_a_3_1: { ...ax, plaintext_sha256: hex(sha256(pt)) },
    },
  };
}

// Checks every entry of a primitives table (the in-file transcription or the file on disk).
// Returns the list of failures; an empty list means it passes.
function verifyPrimitives(table) {
  const failures = [];
  const check = (name, fn) => {
    try {
      if (fn() !== true) failures.push(name);
    } catch (e) {
      failures.push(`${name} (${e.message})`);
    }
  };
  const eq = (a, b) => Buffer.from(a).equals(Buffer.from(b));
  const x = table.x25519;
  for (const v of ['rfc7748_5_2_vector_1', 'rfc7748_5_2_vector_2']) {
    check(`x25519.${v} node:crypto`, () => eq(crypto.diffieHellman({ privateKey: x25519PrivateKey(unhex(x[v].scalar)), publicKey: x25519PublicKey(unhex(x[v].u)) }), unhex(x[v].output)));
    check(`x25519.${v} ladder`, () => eq(x25519Ladder(unhex(x[v].scalar), unhex(x[v].u)), unhex(x[v].output)));
  }
  check('x25519.rfc7748_5_2_iterated', () => {
    let k = unhex(x.rfc7748_5_2_iterated.start);
    let u = Buffer.from(k);
    let kl = Buffer.from(k);
    let ul = Buffer.from(k);
    for (let i = 1; i <= 1000; i++) {
      [k, u] = [dh(k, u), k];
      [kl, ul] = [x25519Ladder(kl, ul), kl];
      if (!eq(k, kl)) return false;
      if (i === 1 && !eq(k, unhex(x.rfc7748_5_2_iterated.after_1))) return false;
    }
    return eq(k, unhex(x.rfc7748_5_2_iterated.after_1000));
  });
  check('x25519.rfc7748_6_1', () => {
    const v = x.rfc7748_6_1;
    return (
      eq(x25519Public(unhex(v.alice_private)), unhex(v.alice_public)) &&
      eq(x25519Public(unhex(v.bob_private)), unhex(v.bob_public)) &&
      eq(dh(unhex(v.alice_private), unhex(v.bob_public)), unhex(v.shared)) &&
      eq(dh(unhex(v.bob_private), unhex(v.alice_public)), unhex(v.shared))
    );
  });
  const lows = x.derived_low_order_refused.values;
  check('x25519.derived_low_order_refused count', () => lows.length === 7);
  for (const { name, u } of lows) {
    check(`x25519.derived_low_order_refused.${name}`, () => {
      const scalars = [x.rfc7748_5_2_vector_1.scalar, x.rfc7748_6_1.alice_private, x.rfc7748_6_1.bob_private];
      for (const s of scalars) {
        if (!isAllZero(x25519Ladder(unhex(s), unhex(u)))) return false;
        try {
          dh(unhex(s), unhex(u));
          return false;
        } catch (e) {
          if (!(e instanceof ProtoError) || e.code !== 'low_order') return false;
        }
      }
      return true;
    });
  }
  const ed = table.ed25519;
  for (const t of ['rfc8032_7_1_test_1', 'rfc8032_7_1_test_2', 'rfc8032_7_1_test_3']) {
    check(`ed25519.${t}`, () => {
      const v = ed[t];
      return (
        eq(ed25519Public(unhex(v.secret_key)), unhex(v.public_key)) &&
        eq(ed25519Sign(unhex(v.secret_key), unhex(v.message)), unhex(v.signature)) &&
        ed25519Verify(unhex(v.public_key), unhex(v.message), unhex(v.signature)) === true
      );
    });
  }
  if (ed.derived_test_1_s_plus_l_refused) {
    check('ed25519.derived_test_1_s_plus_l_refused', () => {
      const v = ed.derived_test_1_s_plus_l_refused;
      const base = unhex(ed.rfc8032_7_1_test_1.signature);
      const sig = unhex(v.signature);
      const s = leToBig(sig.subarray(32));
      return (
        eq(sig.subarray(0, 32), base.subarray(0, 32)) &&
        s === leToBig(base.subarray(32)) + ED25519_L &&
        v.valid === false &&
        ed25519Verify(unhex(v.public_key), unhex(v.message), sig) === false
      );
    });
  }
  for (const [name, v] of Object.entries(table.hkdf_sha256)) {
    check(`hkdf_sha256.${name}`, () => {
      const ikm = unhex(v.ikm);
      const salt = unhex(v.salt);
      const info = unhex(v.info);
      const node = Buffer.from(crypto.hkdfSync('sha256', ikm, salt, info, v.length));
      const byHmac = hkdfByHmac(ikm, salt, info, v.length);
      return eq(node, unhex(v.okm)) && eq(byHmac.okm, unhex(v.okm)) && (v.prk === undefined || eq(byHmac.prk, unhex(v.prk)));
    });
  }
  if (table.hkdf_sha256.derived_length_32_prefix) {
    check('hkdf_sha256.derived_length_32_prefix is a prefix of A.1', () => table.hkdf_sha256.rfc5869_a_1.okm.startsWith(table.hkdf_sha256.derived_length_32_prefix.okm));
  }
  if (table.hkdf_sha256.derived_empty_salt_equals_zero_salt) {
    check('hkdf_sha256.derived_empty_salt_equals_zero_salt matches A.3', () => {
      const d = table.hkdf_sha256.derived_empty_salt_equals_zero_salt;
      const a3 = table.hkdf_sha256.rfc5869_a_3;
      return a3.salt === '' && d.salt === '00'.repeat(32) && d.ikm === a3.ikm && d.okm === a3.okm && d.prk === a3.prk;
    });
  }
  check('hchacha20.draft_xchacha_03_2_2_1', () => {
    const v = table.hchacha20.draft_xchacha_03_2_2_1;
    return eq(hchacha20ByHand(unhex(v.key), unhex(v.nonce)), unhex(v.output)) && eq(hchacha20FromOpenSsl(unhex(v.key), unhex(v.nonce)), unhex(v.output));
  });
  check('xchacha20poly1305.draft_xchacha_03_a_3_1', () => {
    const v = table.xchacha20poly1305.draft_xchacha_03_a_3_1;
    const sealed = unhex(v.ciphertext + v.tag);
    const pt = xchachaOpen(unhex(v.key), unhex(v.nonce), unhex(v.aad), sealed);
    const flipped = Buffer.from(sealed);
    flipped[flipped.length - 1] ^= 1;
    let flippedRefused = false;
    try {
      xchachaOpen(unhex(v.key), unhex(v.nonce), unhex(v.aad), flipped);
    } catch (e) {
      flippedRefused = e instanceof ProtoError && e.code === 'decrypt_failed';
    }
    return (
      pt.length === v.plaintext_length &&
      (v.plaintext_sha256 === undefined || eq(sha256(pt), unhex(v.plaintext_sha256))) &&
      eq(xchachaSeal(unhex(v.key), unhex(v.nonce), unhex(v.aad), pt), sealed) &&
      flippedRefused
    );
  });
  return failures;
}

function selfTestInternals() {
  const failures = [];
  for (const [value, expected] of CBOR_RFC8949_APPENDIX_A) {
    if (hex(cbor(value)) !== expected) failures.push(`CBOR RFC 8949 Appendix A row ${expected}`);
  }
  // HKDF with an empty salt equals HKDF with 32 zero bytes in node:crypto (used by KDF_CK).
  const ikm = labelledBytes('selftest/hkdf-empty-salt', 32);
  const a = Buffer.from(crypto.hkdfSync('sha256', ikm, Buffer.alloc(0), utf8('x'), 64));
  const b = Buffer.from(crypto.hkdfSync('sha256', ikm, Buffer.alloc(32), utf8('x'), 64));
  if (!a.equals(b)) failures.push('hkdfSync empty salt against 32 zero bytes');
  return failures;
}

// ---------------------------------------------------------------------------------------------
// Protocol v2
// ---------------------------------------------------------------------------------------------

const F = unhex(PARAMS.x3dh.f_hex);

function makeParty(name, { spkId, opkId } = {}) {
  const ikPriv = secret(`party/${name}/ik`);
  const sigSeed = secret(`party/${name}/ik_sig`);
  const party = {
    name,
    device_id: labelledUuid(`party/${name}/device`),
    device_id_label: `party/${name}/device`,
    ik: { label: `party/${name}/ik`, priv: ikPriv, pub: x25519Public(ikPriv) },
    ik_sig: { label: `party/${name}/ik_sig`, seed: sigSeed, pub: ed25519Public(sigSeed) },
  };
  if (spkId !== undefined) {
    const priv = secret(`party/${name}/spk/${spkId}`);
    party.spk = { id: spkId, label: `party/${name}/spk/${spkId}`, priv, pub: x25519Public(priv) };
  }
  if (opkId !== undefined) {
    const priv = secret(`party/${name}/opk/${opkId}`);
    party.opk = { id: opkId, label: `party/${name}/opk/${opkId}`, priv, pub: x25519Public(priv) };
  }
  return party;
}

function partyJson(p) {
  const out = {
    device_id: p.device_id,
    device_id_label: p.device_id_label,
    ik: { private_label: p.ik.label, private_hex: hex(p.ik.priv), public_hex: hex(p.ik.pub) },
    ik_sig: { seed_label: p.ik_sig.label, seed_hex: hex(p.ik_sig.seed), public_hex: hex(p.ik_sig.pub) },
  };
  if (p.spk) out.spk = { id: p.spk.id, private_label: p.spk.label, private_hex: hex(p.spk.priv), public_hex: hex(p.spk.pub) };
  if (p.opk) out.opk = { id: p.opk.id, private_label: p.opk.label, private_hex: hex(p.opk.priv), public_hex: hex(p.opk.pub) };
  return out;
}

const spkSignatureMessage = (deviceId, ikPub, spkPub, spkId) => cbor([PARAMS.x3dh.spk_signature.domain, deviceId, need(ikPub, 32, 'IK'), need(spkPub, 32, 'SPK'), spkId]);

function buildAd({ ikA, ikB, ikSigA, ikSigB, devA, devB }) {
  const a = uuidBytes(devA);
  const b = uuidBytes(devB);
  if (a.equals(b)) throw new ProtoError('self_session');
  const ad = cat([PARAMS.ad.ik_type_byte], need(ikA, 32, 'IK_A'), [PARAMS.ad.ik_type_byte], need(ikB, 32, 'IK_B'), [PARAMS.ad.sig_type_byte], need(ikSigA, 32, 'IKsig_A'), [PARAMS.ad.sig_type_byte], need(ikSigB, 32, 'IKsig_B'), a, b);
  if (ad.length !== PARAMS.ad.length) fail('AD length');
  return ad;
}

function parseAd(ad) {
  if (ad.length !== 164 || ad[0] !== 0x05 || ad[33] !== 0x05 || ad[66] !== 0xed || ad[99] !== 0xed) fail('AD layout');
  return {
    ikA: ad.subarray(1, 33), ikB: ad.subarray(34, 66), ikSigA: ad.subarray(67, 99), ikSigB: ad.subarray(100, 132),
    devA: uuidFromBytes(ad.subarray(132, 148)), devB: uuidFromBytes(ad.subarray(148, 164)),
  };
}

// The X3DH key derivation with its parameters as data, shared by the vectors and the --params mode.
function x3dhKdf(dhOutputs, kdf) {
  const km = cat(unhex(kdf.f_hex), ...dhOutputs);
  const okm = hkdf(km, unhex(kdf.salt_hex), utf8(kdf.info_utf8), kdf.length);
  const out = { km };
  let at = 0;
  for (const [name, length] of kdf.split) {
    out[name] = Buffer.from(okm.subarray(at, at + length));
    at += length;
  }
  if (at !== kdf.length) fail('split does not cover the output');
  return out;
}

const initiatorDh = ({ ikPriv, ekPriv, peerIk, peerSpk, peerOpk }) => [dh(ikPriv, peerSpk), dh(ekPriv, peerIk), dh(ekPriv, peerSpk), ...(peerOpk ? [dh(ekPriv, peerOpk)] : [])];
const responderDh = ({ ikPriv, spkPriv, opkPriv, peerIk, peerEk }) => [dh(spkPriv, peerIk), dh(ikPriv, peerEk), dh(spkPriv, peerEk), ...(opkPriv ? [dh(opkPriv, peerEk)] : [])];

function kdfRk(rk, dhOut) {
  const o = hkdf(dhOut, rk, utf8(PARAMS.ratchet.kdf_rk.info_utf8), 64);
  return [Buffer.from(o.subarray(0, 32)), Buffer.from(o.subarray(32, 64))];
}

function kdfCk(ck) {
  const o = hkdf(ck, unhex(PARAMS.ratchet.kdf_ck.salt_hex), utf8(PARAMS.ratchet.kdf_ck.info_utf8), 64);
  return [Buffer.from(o.subarray(0, 32)), Buffer.from(o.subarray(32, 64))];
}

const isId32 = (n) => Number.isSafeInteger(n) && n >= 1 && n <= 2 ** 31 - 1;

function sessionInitWire({ senderDeviceId, recipientDeviceId, ikPub, ikSigPub, ekPub, spkId, opkId }) {
  const w = {
    v: 2,
    sender_device_id: senderDeviceId,
    recipient_device_id: recipientDeviceId,
    sender_ik_pub_b64: b64(ikPub),
    sender_ik_sig_pub_b64: b64(ikSigPub),
    ek_pub_b64: b64(ekPub),
    spk_id: spkId,
    used_opk: opkId !== undefined,
  };
  if (opkId !== undefined) w.opk_id = opkId;
  return w;
}

function parseSessionInit(w) {
  if (!w || typeof w !== 'object' || w.v !== 2) throw new ProtoError('invalid_session_init', 'v');
  const senderDeviceId = canonicalId(w.sender_device_id);
  const recipientDeviceId = canonicalId(w.recipient_device_id);
  const ikPub = strictB64(w.sender_ik_pub_b64, 32, 'invalid_session_init');
  const ikSigPub = strictB64(w.sender_ik_sig_pub_b64, 32, 'invalid_session_init');
  const ekPub = strictB64(w.ek_pub_b64, 32, 'invalid_session_init');
  if (!isId32(w.spk_id)) throw new ProtoError('invalid_session_init', 'spk_id');
  if (typeof w.used_opk !== 'boolean') throw new ProtoError('invalid_session_init', 'used_opk');
  if (w.used_opk !== ('opk_id' in w)) throw new ProtoError('invalid_session_init', 'opk_id present exactly when used_opk');
  if (w.used_opk && !isId32(w.opk_id)) throw new ProtoError('invalid_session_init', 'opk_id');
  return { senderDeviceId, recipientDeviceId, ikPub, ikSigPub, ekPub, spkId: w.spk_id, opkId: w.used_opk ? w.opk_id : undefined };
}

// The initiator's bundle checks in the design's order: signature, then the expected device.
function initiatorBundleChecks(bundle, expectedRecipientDeviceId) {
  if (!bundle || bundle.v !== 2) throw new ProtoError('invalid_bundle', 'v');
  const recipient = canonicalId(bundle.recipient_device_id);
  const ik = strictB64(bundle.ik_pub_b64, 32, 'invalid_bundle');
  const ikSig = strictB64(bundle.ik_sig_pub_b64, 32, 'invalid_bundle');
  const spk = strictB64(bundle.spk_pub_b64, 32, 'invalid_bundle');
  const sig = strictB64(bundle.spk_sig_b64, 64, 'invalid_bundle');
  if (!isId32(bundle.spk_id)) throw new ProtoError('invalid_bundle', 'spk_id');
  if (!ed25519Verify(ikSig, spkSignatureMessage(recipient, ik, spk, bundle.spk_id), sig)) throw new ProtoError('bad_signature', 'SPK signature');
  if (recipient !== canonicalId(expectedRecipientDeviceId)) throw new ProtoError('device_mismatch');
  const opk = 'opk_pub_b64' in bundle ? strictB64(bundle.opk_pub_b64, 32, 'invalid_bundle') : undefined;
  if ((opk !== undefined) !== ('opk_id' in bundle) || (opk !== undefined && !isId32(bundle.opk_id))) throw new ProtoError('invalid_bundle', 'opk');
  return { recipient, ik, ikSig, spk, spkId: bundle.spk_id, opk, opkId: bundle.opk_id };
}

function bundleWire(owner, { withOpk, deviceId = owner.device_id, spkPub = owner.spk.pub, signer = owner.ik_sig.seed }) {
  const w = {
    v: 2,
    recipient_device_id: deviceId,
    ik_pub_b64: b64(owner.ik.pub),
    ik_sig_pub_b64: b64(owner.ik_sig.pub),
    spk_id: owner.spk.id,
    spk_pub_b64: b64(spkPub),
    spk_sig_b64: b64(ed25519Sign(signer, spkSignatureMessage(deviceId, owner.ik.pub, owner.spk.pub, owner.spk.id))),
  };
  if (withOpk) {
    w.opk_id = owner.opk.id;
    w.opk_pub_b64 = b64(owner.opk.pub);
  }
  return w;
}

// The responder bootstrap: reads the SPK and OPK privates without consuming them, builds AD with
// the host's sender device id (the server row) and refuses a differing sidecar id.
function responderBootstrap({ sessionInit, self, prekeys, senderDeviceId }) {
  const si = parseSessionInit(sessionInit);
  const host = canonicalId(senderDeviceId);
  if (si.recipientDeviceId === host || si.senderDeviceId === si.recipientDeviceId) throw new ProtoError('self_session');
  if (si.senderDeviceId !== host) throw new ProtoError('device_mismatch', 'sidecar sender differs from the row');
  if (si.recipientDeviceId !== self.device_id) throw new ProtoError('device_mismatch', 'sidecar recipient is not this device');
  const spk = prekeys.spks.get(si.spkId);
  if (!spk) throw new ProtoError('unknown_spk');
  let opk;
  if (si.opkId !== undefined) {
    opk = prekeys.opks.get(si.opkId);
    if (!opk) throw new ProtoError('unknown_opk');
  }
  const dhs = responderDh({ ikPriv: self.ik.priv, spkPriv: spk.priv, opkPriv: opk?.priv, peerIk: si.ikPub, peerEk: si.ekPub });
  const { sk, km } = x3dhKdf(dhs, PARAMS.x3dh.kdf);
  const ad = buildAd({ ikA: si.ikPub, ikB: self.ik.pub, ikSigA: si.ikSigPub, ikSigB: self.ik_sig.pub, devA: host, devB: self.device_id });
  return { sk, km, dhs, ad, state: initResponder({ sk, ad, spk }), used: { spk_id: si.spkId, ...(opk ? { opk_id: si.opkId } : {}) } };
}

// ---- Double Ratchet state ----

function cloneState(s) {
  const c = (b) => (b ? Buffer.from(b) : null);
  return {
    role: s.role, ad: c(s.ad), rk: c(s.rk), cks: c(s.cks), ckr: c(s.ckr), ns: s.ns, nr: s.nr, pn: s.pn,
    dhs: { priv: c(s.dhs.priv), pub: c(s.dhs.pub) }, dhr: c(s.dhr),
    skipped: s.skipped.map((e) => ({ dh: c(e.dh), n: e.n, mk: c(e.mk) })),
  };
}

function initInitiator({ sk, ad, remoteSpkPub }, draw) {
  const priv = draw(32, 'dhs');
  const pub = x25519Public(priv);
  const [rk, cks] = kdfRk(sk, dh(priv, remoteSpkPub));
  return { role: 'initiator', ad: Buffer.from(ad), rk, cks, ckr: null, ns: 0, nr: 0, pn: 0, dhs: { priv, pub }, dhr: Buffer.from(remoteSpkPub), skipped: [] };
}

function initResponder({ sk, ad, spk }) {
  return { role: 'responder', ad: Buffer.from(ad), rk: Buffer.from(sk), cks: null, ckr: null, ns: 0, nr: 0, pn: 0, dhs: { priv: Buffer.from(spk.priv), pub: Buffer.from(spk.pub) }, dhr: null, skipped: [] };
}

function idsOf(s) {
  const { devA, devB } = parseAd(s.ad);
  return s.role === 'initiator' ? { self: devA, peer: devB } : { self: devB, peer: devA };
}

function parseGrp(g) {
  if (g === undefined || g === null) return null;
  if (typeof g !== 'object' || Array.isArray(g)) throw new ProtoError('invalid_grp', 'not an object');
  if (typeof g.gid !== 'string' || !UUID_RE.test(g.gid)) throw new ProtoError('invalid_grp', 'gid');
  if (!Number.isSafeInteger(g.epoch) || g.epoch < 0) throw new ProtoError('invalid_grp', 'epoch');
  return { gid: g.gid, epoch: g.epoch };
}

function buildH(h) {
  const grp = h.grp ? [uuidBytes(h.grp.gid), h.grp.epoch] : null;
  return cbor([2, PARAMS.header.alg, need(h.nonce, 24, 'nonce'), uuidBytes(h.sender), uuidBytes(h.recipient), need(h.dhPub, 32, 'dh_pub'), h.pn, h.n, grp]);
}

function headerWire(h) {
  const w = { v: 2, alg: PARAMS.header.alg, nonce_b64: b64(h.nonce), sender_device_id: h.sender, recipient_device_id: h.recipient, dh_pub_b64: b64(h.dhPub), pn: h.pn, n: h.n };
  if (h.grp) w.grp = { gid: h.grp.gid, epoch: h.grp.epoch };
  return w;
}

function parseHeaderWire(w) {
  if (!w || typeof w !== 'object' || w.v !== 2) throw new ProtoError('invalid_header', 'v');
  if (w.alg !== PARAMS.header.alg) throw new ProtoError('invalid_header', 'alg');
  const sender = canonicalId(w.sender_device_id);
  const recipient = canonicalId(w.recipient_device_id);
  const nonce = strictB64(w.nonce_b64, 24, 'invalid_header');
  const dhPub = strictB64(w.dh_pub_b64, 32, 'invalid_header');
  if (!Number.isSafeInteger(w.pn) || w.pn < 0 || !Number.isSafeInteger(w.n) || w.n < 0) throw new ProtoError('invalid_header', 'pn or n');
  return { v: 2, nonce, sender, recipient, dhPub, pn: w.pn, n: w.n, grp: parseGrp(w.grp) };
}

function ratchetEncrypt(state, plaintext, grp, draw) {
  const s = cloneState(state);
  if (!s.cks) throw new ProtoError('no_sending_chain');
  const [ck, mk] = kdfCk(s.cks);
  const nonce = draw(24, 'nonce');
  const { self, peer } = idsOf(s);
  const header = { v: 2, nonce, sender: self, recipient: peer, dhPub: s.dhs.pub, pn: s.pn, n: s.ns, grp: parseGrp(grp) };
  const H = buildH(header);
  const aad = cat(s.ad, H);
  const ct = xchachaSeal(mk, nonce, aad, plaintext);
  s.cks = ck;
  s.ns += 1;
  return { state: s, wire: headerWire(header), H, aad, mk, ct };
}

function skipMessageKeys(s, until) {
  if (s.nr + PARAMS.ratchet.max_skip < until) throw new ProtoError('too_many_skipped');
  if (!s.ckr) return;
  while (s.nr < until) {
    const [ck, mk] = kdfCk(s.ckr);
    s.skipped.push({ dh: Buffer.from(s.dhr), n: s.nr, mk });
    if (s.skipped.length > PARAMS.ratchet.skipped_cache) s.skipped.shift();
    s.ckr = ck;
    s.nr += 1;
  }
}

function dhRatchet(s, header, draw) {
  s.pn = s.ns;
  s.ns = 0;
  s.nr = 0;
  s.dhr = Buffer.from(header.dhPub);
  [s.rk, s.ckr] = kdfRk(s.rk, dh(s.dhs.priv, s.dhr));
  const priv = draw(32, 'dhs');
  s.dhs = { priv, pub: x25519Public(priv) };
  [s.rk, s.cks] = kdfRk(s.rk, dh(s.dhs.priv, s.dhr));
}

// Works on a clone; the caller's state is never changed, so a refusal leaves it as it was.
function ratchetDecrypt(state, wire, ct, draw) {
  const header = parseHeaderWire(wire);
  const s = cloneState(state);
  const { self, peer } = idsOf(s);
  if (header.sender !== peer || header.recipient !== self) throw new ProtoError('device_mismatch');
  const H = buildH(header);
  const aad = cat(s.ad, H);
  const at = s.skipped.findIndex((e) => e.dh.equals(header.dhPub) && e.n === header.n);
  if (at >= 0) {
    const { mk } = s.skipped[at];
    const plaintext = xchachaOpen(mk, header.nonce, aad, ct);
    s.skipped.splice(at, 1);
    return { state: s, plaintext, mk, H, aad, header, fromSkipped: true, dhStep: false };
  }
  if (s.dhr && s.dhr.equals(header.dhPub) && header.n < s.nr) throw new ProtoError('replay_detected');
  let dhStep = false;
  if (!s.dhr || !s.dhr.equals(header.dhPub)) {
    skipMessageKeys(s, header.pn);
    dhRatchet(s, header, draw);
    dhStep = true;
  }
  skipMessageKeys(s, header.n);
  const [ck, mk] = kdfCk(s.ckr);
  s.ckr = ck;
  s.nr += 1;
  const plaintext = xchachaOpen(mk, header.nonce, aad, ct);
  return { state: s, plaintext, mk, H, aad, header, fromSkipped: false, dhStep };
}

function serializeState(s) {
  return {
    v: 2,
    role: s.role,
    ad_b64: b64(s.ad),
    rk32_b64: b64(s.rk),
    ck_s32_b64: s.cks ? b64(s.cks) : null,
    ck_r32_b64: s.ckr ? b64(s.ckr) : null,
    ns: s.ns,
    nr: s.nr,
    pn: s.pn,
    dh_self: { priv32_b64: b64(s.dhs.priv), pub32_b64: b64(s.dhs.pub) },
    dh_remote_pub32_b64: s.dhr ? b64(s.dhr) : null,
    skipped: s.skipped.map((e) => ({ dh_pub32_b64: b64(e.dh), n: e.n, mk32_b64: b64(e.mk) })),
  };
}

function deserializeState(o) {
  const k32 = (v) => strictB64(v, 32, 'invalid_state');
  const opt = (v) => (v === null ? null : k32(v));
  if (o.v !== 2 || (o.role !== 'initiator' && o.role !== 'responder')) throw new ProtoError('invalid_state');
  const ad = strictB64(o.ad_b64, 164, 'invalid_state');
  parseAd(ad);
  for (const n of [o.ns, o.nr, o.pn]) if (!Number.isSafeInteger(n) || n < 0) throw new ProtoError('invalid_state');
  const priv = k32(o.dh_self.priv32_b64);
  const pub = k32(o.dh_self.pub32_b64);
  assertBytes(x25519Public(priv), pub, 'deserialized dh_self');
  return {
    role: o.role, ad, rk: k32(o.rk32_b64), cks: opt(o.ck_s32_b64), ckr: opt(o.ck_r32_b64), ns: o.ns, nr: o.nr, pn: o.pn,
    dhs: { priv, pub }, dhr: opt(o.dh_remote_pub32_b64),
    skipped: o.skipped.map((e) => ({ dh: k32(e.dh_pub32_b64), n: e.n, mk: k32(e.mk32_b64) })),
  };
}

// The scripted randomness: draw number, party and purpose name the label, so every draw is listed.
class ScriptedDraws {
  constructor(scope) {
    this.scope = scope;
    this.log = [];
    this.step = undefined;
  }

  draw(party, length, what) {
    const seq = this.log.length + 1;
    const label = `${this.scope}/draw/${String(seq).padStart(2, '0')}/${party}/${what}`;
    const bytes = labelledBytes(label, length);
    this.log.push({ seq, ...(this.step !== undefined ? { step: this.step } : {}), party, what, length, label, hex: hex(bytes) });
    return bytes;
  }

  for(party) {
    return (length, what) => this.draw(party, length, what);
  }
}

// Refusals run with ordinary (unlisted) draws; a labelled throwaway source keeps the run deterministic.
const throwaway = new ScriptedDraws('refusal/throwaway').for('any');

function refusedWith(fn) {
  try {
    fn();
  } catch (e) {
    if (e instanceof ProtoError) return e;
    throw e;
  }
  return null;
}

// expectedCode null: the design names no code, so the vector accepts any typed refusal; the
// generator still checks that its own refusal has the intended reason (reasonCode).
function expectRefusal(name, fn, expectedCode, reasonCode) {
  const e = refusedWith(fn);
  if (!e) fail(`refusal vector ${name} was accepted`);
  const want = expectedCode ?? reasonCode;
  if (want === undefined || want === null) fail(`refusal vector ${name} has neither a code nor a reason`);
  if (e.code !== want) fail(`refusal vector ${name}: got ${e.code}, expected ${want}`);
  return e;
}

function nonCanonicalVariants(id) {
  return [
    { name: 'uppercase', value: id.toUpperCase() },
    { name: 'one_uppercase_letter', value: id.replace(/[a-f]/, (c) => c.toUpperCase()) },
    { name: 'braces', value: `{${id}}` },
    { name: 'urn_prefix', value: `urn:uuid:${id}` },
    { name: 'no_hyphens', value: id.replaceAll('-', '') },
    { name: 'hyphen_moved', value: `${id.slice(0, 7)}-${id.slice(7, 8)}${id.slice(9)}` },
    { name: 'leading_space', value: ` ${id}` },
    { name: 'trailing_newline', value: `${id}\n` },
    { name: 'too_short', value: id.slice(0, 35) },
    { name: 'non_hex_letter', value: `${id.slice(0, 35)}g` },
    { name: 'lone_surrogate', value: `${id.slice(0, 35)}\ud800` },
    { name: 'empty', value: '' },
  ];
}

// ---------------------------------------------------------------------------------------------
// x3dh-v2.json
// ---------------------------------------------------------------------------------------------

const ALICE = makeParty('alice');
const BOB = makeParty('bob', { spkId: 7, opkId: 300 });
const MALLORY = makeParty('mallory');
const CAROL_DEVICE = labelledUuid('party/carol/device');
const GROUP_ID = labelledUuid('group/gid');

function bobPrekeys({ withOpk }) {
  return { spks: new Map([[BOB.spk.id, BOB.spk]]), opks: new Map(withOpk ? [[BOB.opk.id, BOB.opk]] : []) };
}

function buildX3dhScenario(name, withOpk, plaintextText) {
  const draws = new ScriptedDraws(`x3dh/${name}`);
  const bundle = bundleWire(BOB, { withOpk });
  const checked = initiatorBundleChecks(bundle, BOB.device_id);
  // Initiator: EK, then DHs (design.md:216).
  const ekPriv = draws.draw('alice', 32, 'ek');
  const ekPub = x25519Public(ekPriv);
  const dhI = initiatorDh({ ikPriv: ALICE.ik.priv, ekPriv, peerIk: checked.ik, peerSpk: checked.spk, peerOpk: checked.opk });
  const { sk, km } = x3dhKdf(dhI, PARAMS.x3dh.kdf);
  const skWithoutF = x3dhKdf(dhI, { ...PARAMS.x3dh.kdf, f_hex: '' }).sk;
  const ad = buildAd({ ikA: ALICE.ik.pub, ikB: checked.ik, ikSigA: ALICE.ik_sig.pub, ikSigB: checked.ikSig, devA: ALICE.device_id, devB: checked.recipient });
  const sessionInit = sessionInitWire({ senderDeviceId: ALICE.device_id, recipientDeviceId: checked.recipient, ikPub: ALICE.ik.pub, ikSigPub: ALICE.ik_sig.pub, ekPub, spkId: checked.spkId, opkId: withOpk ? checked.opkId : undefined });
  const alice0 = initInitiator({ sk, ad, remoteSpkPub: checked.spk }, draws.for('alice'));
  const aliceInitDh = dh(alice0.dhs.priv, checked.spk);
  const enc = ratchetEncrypt(alice0, utf8(plaintextText), null, draws.for('alice'));

  // Responder: bootstrap from the sidecar and the row's sender device, then the first decrypt (one draw).
  const boot = responderBootstrap({ sessionInit, self: BOB, prekeys: bobPrekeys({ withOpk }), senderDeviceId: ALICE.device_id });
  if (boot.dhs.length !== dhI.length) fail('DH count');
  boot.dhs.forEach((d, i) => assertBytes(d, dhI[i], `DH${i + 1} initiator against responder`));
  assertBytes(boot.sk, sk, 'SK initiator against responder');
  assertBytes(boot.ad, ad, 'AD initiator against responder');
  const dec = ratchetDecrypt(boot.state, enc.wire, enc.ct, draws.for('bob'));
  assertBytes(dec.plaintext, utf8(plaintextText), 'first message plaintext');
  if (!dec.dhStep) fail('the first decrypt must take a DH step');

  const dhNames = ['dh1', 'dh2', 'dh3', 'dh4'];
  const scenario = {
    name,
    one_time_prekey_used: withOpk,
    parties: { alice: partyJson(ALICE), bob: partyJson(BOB) },
    draws: draws.log,
    bundle: {
      spk_signature_message_cbor_hex: hex(spkSignatureMessage(BOB.device_id, BOB.ik.pub, BOB.spk.pub, BOB.spk.id)),
      spk_signature_hex: hex(strictB64(bundle.spk_sig_b64, 64, 'x')),
      wire: bundle,
    },
    expected_recipient_device_id: BOB.device_id,
    x3dh: {
      ek_private_hex: hex(ekPriv),
      ek_public_hex: hex(ekPub),
      ...Object.fromEntries(dhI.map((d, i) => [`${dhNames[i]}_hex`, hex(d)])),
      km_hex: hex(km),
      km_length: km.length,
      sk_hex: hex(sk),
      sk_without_f_hex: hex(skWithoutF),
    },
    ad: { hex: hex(ad), length: ad.length },
    session_init: sessionInit,
    responder_used: boot.used,
    initiator_ratchet_init: {
      dhs_private_hex: hex(alice0.dhs.priv),
      dhs_public_hex: hex(alice0.dhs.pub),
      dh_out_hex: hex(aliceInitDh),
      rk_hex: hex(alice0.rk),
      ck_s_hex: hex(alice0.cks),
      state: serializeState(alice0),
    },
    responder_ratchet_init: { state: serializeState(boot.state) },
    first_message: {
      plaintext_utf8: plaintextText,
      plaintext_hex: hex(utf8(plaintextText)),
      message_key_hex: hex(enc.mk),
      nonce_hex: hex(strictB64(enc.wire.nonce_b64, 24, 'nonce')),
      header: enc.wire,
      h_cbor_hex: hex(enc.H),
      aad_hex: hex(enc.aad),
      ciphertext_hex: hex(enc.ct),
      tag_hex: hex(enc.ct.subarray(enc.ct.length - 16)),
    },
    initiator_state_after_first_encrypt: serializeState(enc.state),
    responder_state_after_first_decrypt: serializeState(dec.state),
    refusals: [],
  };

  const r = scenario.refusals;
  const respond = (si, opts = {}) => () => {
    const b = responderBootstrap({ sessionInit: si, self: BOB, prekeys: opts.prekeys ?? bobPrekeys({ withOpk }), senderDeviceId: opts.senderDeviceId ?? ALICE.device_id });
    ratchetDecrypt(b.state, enc.wire, enc.ct, throwaway);
  };
  const add = (vector, fn, reasonCode) => {
    const e = expectRefusal(`${name}/${vector.name}`, fn, vector.expected_code, reasonCode);
    r.push({ ...vector, refusal: e.message });
  };

  if (!withOpk) {
    const swapped = { ...sessionInit, sender_ik_sig_pub_b64: b64(MALLORY.ik_sig.pub) };
    add({ name: 'swapped_sender_ik_sig_pub', what: 'session_init names another Ed25519 key (mallory\'s); the responder builds AD with it and the first message fails; no prekey is consumed', session_init: swapped, sender_device_id: ALICE.device_id, deliver: 'first_message', expected_code: 'decrypt_failed' }, respond(swapped));

    add({ name: 'sk_without_f', what: 'a responder state built from SK derived without F (sk_without_f_hex) cannot read the first message', sk_hex: hex(skWithoutF), ad_hex: hex(ad), deliver: 'first_message', expected_code: 'decrypt_failed' }, () => {
      ratchetDecrypt(initResponder({ sk: skWithoutF, ad, spk: BOB.spk }), enc.wire, enc.ct, throwaway);
    });

    for (const { name: lowName, u } of PUBLISHED.x25519.derived_low_order_refused.values) {
      const lowEk = { ...sessionInit, ek_pub_b64: b64(unhex(u)) };
      add({ name: `low_order_ek_${lowName}`, what: 'session_init carries a low-order EK; DH2 and DH3 are all zero and the bootstrap refuses', session_init: lowEk, sender_device_id: ALICE.device_id, expected_code: null }, respond(lowEk), 'low_order');
    }

    const upper = { ...sessionInit, sender_device_id: ALICE.device_id.toUpperCase() };
    add({ name: 'non_canonical_sender_device_id', what: 'session_init sender_device_id in uppercase', session_init: upper, sender_device_id: ALICE.device_id, expected_code: 'invalid_device_id' }, respond(upper));

    const selfInit = { ...sessionInit, sender_device_id: BOB.device_id };
    add({ name: 'equal_device_ids', what: 'session_init sender and recipient are the same device, and the row names that device', session_init: selfInit, sender_device_id: BOB.device_id, expected_code: 'self_session' }, respond(selfInit, { senderDeviceId: BOB.device_id }));

    const otherSender = { ...sessionInit, sender_device_id: CAROL_DEVICE };
    add({ name: 'sidecar_sender_differs_from_row', what: 'session_init names another sender device than the server row\'s sender_device_id', session_init: otherSender, sender_device_id: ALICE.device_id, expected_code: 'device_mismatch' }, respond(otherSender));

    const unknownSpk = { ...sessionInit, spk_id: BOB.spk.id + 1 };
    add({ name: 'unknown_spk', what: 'session_init names a signed prekey id the responder does not hold', session_init: unknownSpk, sender_device_id: ALICE.device_id, expected_code: 'unknown_spk' }, respond(unknownSpk));

    const opkWithoutUse = { ...sessionInit, opk_id: BOB.opk.id };
    add({ name: 'opk_id_without_used_opk', what: 'session_init has opk_id while used_opk is false', session_init: opkWithoutUse, sender_device_id: ALICE.device_id, expected_code: null }, respond(opkWithoutUse), 'invalid_session_init');

    const { sender_ik_sig_pub_b64: _dropped, ...noSigKey } = sessionInit;
    add({ name: 'missing_sender_ik_sig_pub', what: 'session_init without sender_ik_sig_pub_b64', session_init: noSigKey, sender_device_id: ALICE.device_id, expected_code: null }, respond(noSigKey), 'invalid_session_init');

    const otherDeviceBundle = bundleWire(BOB, { withOpk: false, deviceId: CAROL_DEVICE });
    add({ name: 'bundle_for_another_device', what: 'a correctly signed bundle that names another device than the one asked for (initiator side)', bundle: otherDeviceBundle, expected_recipient_device_id: BOB.device_id, expected_code: 'device_mismatch' }, () => initiatorBundleChecks(otherDeviceBundle, BOB.device_id));

    const badSigBundle = { ...bundle, spk_pub_b64: b64(MALLORY.ik.pub) };
    add({ name: 'bundle_bad_signature', what: 'the bundle\'s SPK was replaced, so its signature fails (initiator side, before any pin or DH)', bundle: badSigBundle, expected_recipient_device_id: BOB.device_id, expected_code: null }, () => initiatorBundleChecks(badSigBundle, BOB.device_id), 'bad_signature');
  } else {
    add({ name: 'first_message_after_opk_deleted', what: 'the first message delivered again after the responder deleted the one-time prekey it used', session_init: sessionInit, sender_device_id: ALICE.device_id, prekeys_held: { spk_ids: [BOB.spk.id], opk_ids: [] }, deliver: 'first_message', expected_code: 'unknown_opk' }, respond(sessionInit, { prekeys: bobPrekeys({ withOpk: false }) }));
  }
  return scenario;
}

function buildX3dhFile() {
  const noOpk = buildX3dhScenario('no_opk', false, 'hello from alice');
  const withOpk = buildX3dhScenario('with_opk', true, 'first message, one-time prekey');
  if (noOpk.x3dh.km_length !== 128 || withOpk.x3dh.km_length !== 160) fail('KM lengths');

  const adCases = [];
  const base = { ikA: ALICE.ik.pub, ikB: BOB.ik.pub, ikSigA: ALICE.ik_sig.pub, ikSigB: BOB.ik_sig.pub };
  const adInput = (devA, devB) => ({ ik_a_hex: hex(base.ikA), ik_b_hex: hex(base.ikB), ik_sig_a_hex: hex(base.ikSigA), ik_sig_b_hex: hex(base.ikSigB), dev_a: devA, dev_b: devB });
  adCases.push({ name: 'valid', input: adInput(ALICE.device_id, BOB.device_id), ad_hex: hex(buildAd({ ...base, devA: ALICE.device_id, devB: BOB.device_id })) });
  expectRefusal('ad/equal', () => buildAd({ ...base, devA: ALICE.device_id, devB: ALICE.device_id }), 'self_session');
  adCases.push({ name: 'equal_device_ids', input: adInput(ALICE.device_id, ALICE.device_id), expected_code: 'self_session' });
  for (const v of nonCanonicalVariants(ALICE.device_id)) {
    expectRefusal(`ad/${v.name}`, () => buildAd({ ...base, devA: v.value, devB: BOB.device_id }), 'invalid_device_id');
    adCases.push({ name: `non_canonical_dev_a_${v.name}`, input: adInput(v.value, BOB.device_id), expected_code: 'invalid_device_id' });
  }

  return {
    about: 'X3DH v2 vectors (design.md §3.1, §3.2, §3.6) generated by scripts/gen-vectors-v2.mjs from labelled secrets; every byte here was computed on both sides and the two sides agree. Draws are listed in order; feed them to a scripted-randomness provider in that order. Refusal vectors use ordinary randomness; each must fail with expected_code (null: any typed refusal) and leave every stored state and prekey unchanged.',
    parameters: { f_hex: PARAMS.x3dh.f_hex, kdf: PARAMS.x3dh.kdf, dh_order: PARAMS.x3dh.dh_order.value, ad: PARAMS.ad.layout, spk_signature: PARAMS.x3dh.spk_signature.value, labels: PARAMS.labels.rule, label_prefix: PARAMS.labels.prefix },
    other_keys: { mallory_ik_sig_public_hex: hex(MALLORY.ik_sig.pub), mallory_ik_sig_seed_label: MALLORY.ik_sig.label, mallory_ik_public_hex: hex(MALLORY.ik.pub), mallory_ik_private_label: MALLORY.ik.label, carol_device_id: CAROL_DEVICE, carol_device_id_label: 'party/carol/device' },
    scenarios: [noOpk, withOpk],
    ad_builder: adCases,
  };
}

// ---------------------------------------------------------------------------------------------
// ratchet-v2.json
// ---------------------------------------------------------------------------------------------

function buildRatchetFile() {
  const setupDraws = new ScriptedDraws('ratchet/setup');
  const ekPriv = setupDraws.draw('alice', 32, 'ek');
  const ekPub = x25519Public(ekPriv);
  const dhI = initiatorDh({ ikPriv: ALICE.ik.priv, ekPriv, peerIk: BOB.ik.pub, peerSpk: BOB.spk.pub });
  const { sk } = x3dhKdf(dhI, PARAMS.x3dh.kdf);
  const ad = buildAd({ ikA: ALICE.ik.pub, ikB: BOB.ik.pub, ikSigA: ALICE.ik_sig.pub, ikSigB: BOB.ik_sig.pub, devA: ALICE.device_id, devB: BOB.device_id });
  const sessionInit = sessionInitWire({ senderDeviceId: ALICE.device_id, recipientDeviceId: BOB.device_id, ikPub: ALICE.ik.pub, ikSigPub: ALICE.ik_sig.pub, ekPub, spkId: BOB.spk.id });
  const boot = responderBootstrap({ sessionInit, self: BOB, prekeys: bobPrekeys({ withOpk: false }), senderDeviceId: ALICE.device_id });
  assertBytes(boot.sk, sk, 'ratchet setup SK');

  const draws = new ScriptedDraws('ratchet');
  const st = { alice: null, bob: null };
  const other = { alice: 'bob', bob: 'alice' };
  const sent = new Map();
  const messages = [];
  const steps = [];
  const snapshots = new Map();
  let stepNo = 0;

  const begin = () => {
    stepNo += 1;
    draws.step = stepNo;
    return stepNo;
  };
  const drawsOf = (n) => draws.log.filter((d) => d.step === n).map((d) => d.seq);
  const finish = (entry) => {
    steps.push({ ...entry, draw_seqs: drawsOf(entry.step) });
    snapshots.set(entry.step, { alice: st.alice && cloneState(st.alice), bob: st.bob && cloneState(st.bob) });
  };

  let n = begin();
  st.alice = initInitiator({ sk, ad, remoteSpkPub: BOB.spk.pub }, draws.for('alice'));
  finish({ step: n, actor: 'alice', op: 'ratchet_init_initiator', state_after: serializeState(st.alice) });
  n = begin();
  st.bob = initResponder({ sk, ad, spk: BOB.spk });
  finish({ step: n, actor: 'bob', op: 'ratchet_init_responder', state_after: serializeState(st.bob) });

  const encrypt = (who, id, text, grp = null) => {
    const s = begin();
    const r = ratchetEncrypt(st[who], utf8(text), grp, draws.for(who));
    st[who] = r.state;
    sent.set(id, { wire: r.wire, ct: r.ct, text });
    messages.push({
      id, from: who, to: other[who], plaintext_utf8: text, plaintext_hex: hex(utf8(text)),
      message_key_hex: hex(r.mk), header: r.wire, h_cbor_hex: hex(r.H), aad_hex: hex(r.aad), ciphertext_hex: hex(r.ct),
    });
    finish({ step: s, actor: who, op: 'encrypt', message: id, state_after: serializeState(st[who]) });
  };
  const decrypt = (who, id) => {
    const s = begin();
    const m = sent.get(id);
    const r = ratchetDecrypt(st[who], m.wire, m.ct, draws.for(who));
    assertBytes(r.plaintext, utf8(m.text), `decrypt ${id}`);
    st[who] = r.state;
    finish({ step: s, actor: who, op: 'decrypt', message: id, expect_plaintext_hex: hex(r.plaintext), dh_step: r.dhStep, from_skipped_key: r.fromSkipped, message_key_hex: hex(r.mk), state_after: serializeState(st[who]) });
  };
  const saveReload = (who) => {
    const s = begin();
    const text = JSON.stringify(serializeState(st[who]));
    st[who] = deserializeState(JSON.parse(text));
    if (JSON.stringify(serializeState(st[who])) !== text) fail('save and reload changed the state');
    finish({ step: s, actor: who, op: 'save_and_reload', serialized: JSON.parse(text) });
  };

  const grp = { gid: GROUP_ID, epoch: 300 };
  encrypt('alice', 'm0', '');
  encrypt('alice', 'm1', 'Grüße aus Zürich – ✓ 🔐');
  encrypt('alice', 'm2', 'third message');
  decrypt('bob', 'm0');
  decrypt('bob', 'm2');
  saveReload('bob');
  encrypt('bob', 'r0', 'reply zero');
  encrypt('bob', 'r1', 'réponse un — ½');
  decrypt('alice', 'r1');
  decrypt('alice', 'r0');
  encrypt('alice', 'm3', 'group-slot message', grp);
  decrypt('bob', 'm3');
  decrypt('bob', 'm1');
  saveReload('alice');
  encrypt('bob', 'r2', 'last one');
  decrypt('alice', 'r2');

  const stepOf = (op, actor, message) => steps.find((s) => s.op === op && s.actor === actor && (message === undefined || s.message === message)).step;

  // Refusal vectors: the receiver's state after a step, a delivery, the expected code, state unchanged.
  const refusals = [];
  const refuse = ({ name, what, afterStep, receiver, wire, ct, expected_code, reason, state }) => {
    const before = state ?? snapshots.get(afterStep)[receiver];
    const text = JSON.stringify(serializeState(before));
    const e = expectRefusal(`ratchet/${name}`, () => ratchetDecrypt(before, wire, ct, throwaway), expected_code, reason);
    if (JSON.stringify(serializeState(before)) !== text) fail(`refusal ${name} changed the state`);
    refusals.push({ name, what, ...(afterStep !== undefined ? { after_step: afterStep } : {}), receiver, state_before: JSON.parse(text), deliver: { header: wire, ciphertext_hex: hex(ct) }, expected_code, refusal: e.message, state_unchanged: true });
  };
  const msg = (id) => sent.get(id);
  const afterBobM0 = stepOf('decrypt', 'bob', 'm0');
  const afterBobM2 = stepOf('decrypt', 'bob', 'm2');

  refuse({ name: 'current_chain_replay', what: 'm0 again after bob read m0 and m2 on the same chain (n < nr, no skipped key)', afterStep: afterBobM2, receiver: 'bob', wire: msg('m0').wire, ct: msg('m0').ct, expected_code: 'replay_detected' });
  refuse({ name: 'current_chain_replay_of_used_skipped_key', what: 'r0 again after alice read it from its skipped key, on her current receiving chain', afterStep: stepOf('decrypt', 'alice', 'r0'), receiver: 'alice', wire: msg('r0').wire, ct: msg('r0').ct, expected_code: 'replay_detected' });
  refuse({ name: 'old_chain_replay', what: 'm0 again after bob stepped to alice\'s next ratchet key; the trial DH step fails the AEAD', afterStep: stepOf('decrypt', 'bob', 'm1'), receiver: 'bob', wire: msg('m0').wire, ct: msg('m0').ct, expected_code: 'decrypt_failed' });
  {
    const ct = Buffer.from(msg('m1').ct);
    ct[3] ^= 0x01;
    refuse({ name: 'flipped_ciphertext_bit', what: 'm1 with one ciphertext bit flipped', afterStep: afterBobM0, receiver: 'bob', wire: msg('m1').wire, ct, expected_code: 'decrypt_failed' });
  }
  {
    const ct = Buffer.from(msg('m1').ct);
    ct[ct.length - 1] ^= 0x80;
    refuse({ name: 'flipped_tag_bit', what: 'm1 with one tag bit flipped', afterStep: afterBobM0, receiver: 'bob', wire: msg('m1').wire, ct, expected_code: 'decrypt_failed' });
  }
  refuse({ name: 'changed_n', what: 'm1 with header n changed from 1 to 2', afterStep: afterBobM0, receiver: 'bob', wire: { ...msg('m1').wire, n: 2 }, ct: msg('m1').ct, expected_code: 'decrypt_failed' });
  refuse({ name: 'changed_pn', what: 'm3 with header pn changed from 3 to 4', afterStep: stepOf('encrypt', 'alice', 'm3'), receiver: 'bob', wire: { ...msg('m3').wire, pn: 4 }, ct: msg('m3').ct, expected_code: 'decrypt_failed' });
  {
    const adOther = buildAd({ ikA: ALICE.ik.pub, ikB: BOB.ik.pub, ikSigA: ALICE.ik_sig.pub, ikSigB: MALLORY.ik_sig.pub, devA: ALICE.device_id, devB: BOB.device_id });
    refuse({ name: 'ad_names_another_ed25519_key', what: 'a responder state whose AD names another Ed25519 key for bob (mallory\'s) cannot read m0', receiver: 'bob', state: initResponder({ sk, ad: adOther, spk: BOB.spk }), wire: msg('m0').wire, ct: msg('m0').ct, expected_code: 'decrypt_failed' });
  }
  refuse({ name: 'header_sender_differs_from_ad', what: 'm1 with dev_sender replaced by a third canonical device id; refused before the AEAD', afterStep: afterBobM0, receiver: 'bob', wire: { ...msg('m1').wire, sender_device_id: CAROL_DEVICE }, ct: msg('m1').ct, expected_code: 'device_mismatch' });
  refuse({ name: 'header_recipient_differs_from_ad', what: 'm1 with dev_recipient replaced by a third canonical device id; refused before the AEAD', afterStep: afterBobM0, receiver: 'bob', wire: { ...msg('m1').wire, recipient_device_id: CAROL_DEVICE }, ct: msg('m1').ct, expected_code: 'device_mismatch' });
  refuse({ name: 'header_sender_non_canonical', what: 'm1 with dev_sender in uppercase', afterStep: afterBobM0, receiver: 'bob', wire: { ...msg('m1').wire, sender_device_id: ALICE.device_id.toUpperCase() }, ct: msg('m1').ct, expected_code: 'invalid_device_id' });
  refuse({ name: 'header_sender_equals_recipient', what: 'm1 with dev_sender set to bob\'s own id', afterStep: afterBobM0, receiver: 'bob', wire: { ...msg('m1').wire, sender_device_id: BOB.device_id }, ct: msg('m1').ct, expected_code: 'device_mismatch' });
  const afterAliceM3 = stepOf('encrypt', 'alice', 'm3');
  const badGrps = [
    { name: 'gid_uppercase', grp: { gid: GROUP_ID.toUpperCase(), epoch: 300 } },
    { name: 'gid_not_uuid', grp: { gid: 'group-1', epoch: 300 } },
    { name: 'epoch_negative', grp: { gid: GROUP_ID, epoch: -1 } },
    { name: 'epoch_fraction', grp: { gid: GROUP_ID, epoch: 1.5 } },
    { name: 'epoch_unsafe_integer', grp: { gid: GROUP_ID, epoch: 2 ** 53 } },
    { name: 'epoch_string', grp: { gid: GROUP_ID, epoch: '300' } },
    { name: 'epoch_missing', grp: { gid: GROUP_ID } },
    { name: 'gid_missing', grp: { epoch: 300 } },
    { name: 'array', grp: [GROUP_ID, 300] },
    { name: 'string', grp: GROUP_ID },
  ];
  for (const g of badGrps) {
    refuse({ name: `malformed_grp_${g.name}`, what: 'm3 with a malformed grp', afterStep: afterAliceM3, receiver: 'bob', wire: { ...msg('m3').wire, grp: g.grp }, ct: msg('m3').ct, expected_code: null, reason: 'invalid_grp' });
  }
  {
    const e = expectRefusal('ratchet/no_sending_chain', () => ratchetEncrypt(initResponder({ sk, ad, spk: BOB.spk }), utf8('x'), null, throwaway), 'no_sending_chain');
    refusals.push({ name: 'encrypt_without_sending_chain', what: 'a fresh responder state (no CKs) asked to encrypt', receiver: 'bob', state_before: serializeState(initResponder({ sk, ad, spk: BOB.spk })), encrypt_plaintext_hex: hex(utf8('x')), expected_code: 'no_sending_chain', refusal: e.message, state_unchanged: true });
  }

  return {
    about: 'Double Ratchet v2 script (design.md §3.3, §3.4, §3.6) generated by scripts/gen-vectors-v2.mjs. Run the steps in order with one scripted-randomness queue holding the draws in seq order; every encrypt must give the listed bytes and every decrypt the listed plaintext; state_after is the state serialized as design.md:208 describes. save_and_reload steps serialize and deserialize through the public serializers. m3 carries a filled grp slot. Refusal vectors use ordinary randomness; each must fail with expected_code (null: any typed refusal) and leave state_before unchanged.',
    parameters: { kdf_rk: PARAMS.ratchet.kdf_rk, kdf_ck: PARAMS.ratchet.kdf_ck, aead: PARAMS.ratchet.aead.value, aad: PARAMS.ratchet.aad.value, header: PARAMS.header.h, max_skip: PARAMS.ratchet.max_skip, labels: PARAMS.labels.rule, label_prefix: PARAMS.labels.prefix },
    setup: {
      what: 'X3DH without a one-time prekey from the same parties as x3dh-v2.json; the ratchet starts from sk and ad. A test that bootstraps through X3DH instead draws the EK below first.',
      parties: { alice: partyJson(ALICE), bob: partyJson(BOB) },
      x3dh_draws: setupDraws.log,
      session_init: sessionInit,
      sk_hex: hex(sk),
      ad_hex: hex(ad),
      group_id: GROUP_ID,
      group_id_label: 'group/gid',
    },
    draws: draws.log,
    steps,
    messages,
    refusals,
  };
}

// ---------------------------------------------------------------------------------------------
// aead-edges.json and spk-sig-msg-v1.json
// ---------------------------------------------------------------------------------------------

function buildAeadFile() {
  const { plaintext_lengths: pls, aad_lengths: als } = PARAMS.aead_edges;
  const pairs = [];
  for (const pl of pls) {
    for (const al of als) if (pl < 1000 || al === 17) pairs.push([pl, al]);
  }
  const cases = pairs.map(([pl, al]) => {
    const name = `pt${pl}_aad${al}`;
    const key = labelledBytes(`aead/${name}/key`, 32);
    const nonce = labelledBytes(`aead/${name}/nonce`, 24);
    const aad = labelledBytes(`aead/${name}/aad`, al);
    const pt = labelledBytes(`aead/${name}/plaintext`, pl);
    const sealed = xchachaSeal(key, nonce, aad, pt);
    assertBytes(xchachaOpen(key, nonce, aad, sealed), pt, `aead ${name} round trip`);
    const { subkey, nonce12 } = xchachaParts(key, nonce);
    return {
      name, plaintext_length: pl, aad_length: al,
      key_label: `aead/${name}/key`, key_hex: hex(key), nonce_label: `aead/${name}/nonce`, nonce_hex: hex(nonce),
      aad_label: `aead/${name}/aad`, aad_hex: hex(aad), plaintext_label: `aead/${name}/plaintext`, plaintext_hex: hex(pt),
      hchacha20_subkey_hex: hex(subkey), chacha20_nonce12_hex: hex(nonce12),
      ciphertext_with_tag_hex: hex(sealed),
    };
  });

  const draws = new ScriptedDraws('aead/seal_local_v2');
  const key = labelledBytes('aead/seal_local_v2/key', 32);
  const aad = cbor(['moretag/self/v1', ALICE.device_id]);
  const nonce = draws.draw('alice', 24, 'nonce');
  const text = 'note to self ✓';
  const sealed = xchachaSeal(key, nonce, aad, utf8(text));
  assertBytes(xchachaOpen(key, nonce, aad, sealed), utf8(text), 'sealLocalV2 round trip');

  return {
    about: 'XChaCha20-Poly1305 edge lengths (design.md:388) and one sealLocalV2 case (design.md:234), generated by scripts/gen-vectors-v2.mjs. ciphertext_with_tag_hex is the ciphertext followed by the 16-byte tag. The subkey and 12-byte nonce follow draft-irtf-cfrg-xchacha-03 §2.3.',
    parameters: { plaintext_lengths: pls, aad_lengths: als, pairing: 'every plaintext length up to 65 with every AAD length; 16,500 with AAD length 17', labels: PARAMS.labels.rule, label_prefix: PARAMS.labels.prefix },
    cases,
    seal_local_v2: {
      what: 'sealLocalV2(key, aad, plaintext) with one 24-byte nonce draw; the AAD is the host\'s CBOR ["moretag/self/v1", device_id]',
      key_label: 'aead/seal_local_v2/key',
      key_hex: hex(key),
      device_id: ALICE.device_id,
      aad_cbor_hex: hex(aad),
      draws: draws.log,
      plaintext_utf8: text,
      plaintext_hex: hex(utf8(text)),
      header: { v: 2, kind: 'self', nonce: b64(nonce) },
      ciphertext_with_tag_hex: hex(sealed),
    },
  };
}

function buildSpkSigFile() {
  const message = spkSignatureMessage(BOB.device_id, BOB.ik.pub, BOB.spk.pub, BOB.spk.id);
  const signature = ed25519Sign(BOB.ik_sig.seed, message);
  if (!ed25519Verify(BOB.ik_sig.pub, message, signature)) fail('SPK signature');
  return {
    about: 'The signed-prekey signature, unchanged in v2 (design.md:137): Ed25519 by IKsig over CBOR ["moretag/x3dh/spk/v1", device_id, IK, SPK, spk_id], device_id a text string, IK and SPK byte strings, spk_id an unsigned integer, shortest form. Generated by scripts/gen-vectors-v2.mjs from labelled secrets; the generator\'s author could not read the earlier spk-sig-msg-v1.json, so its field names and inputs are this generator\'s.',
    domain: PARAMS.x3dh.spk_signature.domain,
    device_id: BOB.device_id,
    device_id_label: BOB.device_id_label,
    ik_public_hex: hex(BOB.ik.pub),
    ik_private_label: BOB.ik.label,
    spk_id: BOB.spk.id,
    spk_public_hex: hex(BOB.spk.pub),
    spk_private_label: BOB.spk.label,
    ik_sig_seed_label: BOB.ik_sig.label,
    ik_sig_seed_hex: hex(BOB.ik_sig.seed),
    ik_sig_public_hex: hex(BOB.ik_sig.pub),
    message_cbor_hex: hex(message),
    signature_hex: hex(signature),
  };
}

// ---------------------------------------------------------------------------------------------
// --params: the X3DH KDF with the info string, output length and split given as data
// ---------------------------------------------------------------------------------------------

function key32(h, what) {
  const b = unhex(h);
  if (b.length === 33 && b[0] === 0x05) return b.subarray(1); // Encode(PK): type byte then the key
  if (b.length !== 32) fail(`${what}: 32 bytes, or 33 starting with 0x05`);
  return b;
}

// The file: { kdf: { f_hex, salt_hex, info_utf8, length, split: [[name, length], ...] },
//   cases: [ { name, role: "responder", self: { ik_private, spk_private, opk_private? },
//              peer: { ik_public, ek_public }, expect: { <split name>: hex } }
//            | { name, role: "initiator", self: { ik_private, ek_private },
//              peer: { ik_public, spk_public, opk_public? }, expect: { ... } } ] }
function runParams(file) {
  const spec = JSON.parse(fs.readFileSync(file, 'utf8'));
  const kdf = spec.kdf;
  let allSame = true;
  const results = spec.cases.map((c) => {
    const dhs = c.role === 'responder'
      ? responderDh({ ikPriv: key32(c.self.ik_private, 'ik_private'), spkPriv: key32(c.self.spk_private, 'spk_private'), opkPriv: c.self.opk_private && key32(c.self.opk_private, 'opk_private'), peerIk: key32(c.peer.ik_public, 'peer ik'), peerEk: key32(c.peer.ek_public, 'peer ek') })
      : initiatorDh({ ikPriv: key32(c.self.ik_private, 'ik_private'), ekPriv: key32(c.self.ek_private, 'ek_private'), peerIk: key32(c.peer.ik_public, 'peer ik'), peerSpk: key32(c.peer.spk_public, 'peer spk'), peerOpk: c.peer.opk_public && key32(c.peer.opk_public, 'peer opk') });
    const out = x3dhKdf(dhs, kdf);
    const compared = Object.entries(c.expect ?? {}).map(([name, want]) => {
      const same = out[name] !== undefined && hex(out[name]) === want;
      if (!same) allSame = false;
      return { output: name, same };
    });
    return { name: c.name, role: c.role, dh_count: dhs.length, compared };
  });
  process.stdout.write(`${JSON.stringify({ kdf: { info_utf8: kdf.info_utf8, length: kdf.length, split: kdf.split, f: kdf.f_hex.length > 0, salt_length: kdf.salt_hex.length / 2 }, results, outcome: allSame ? 'same' : 'different' }, null, 2)}\n`);
  return allSame ? 0 : 1;
}

// The --params code path, run with the v2 parameters, must reproduce the vectors' SK.
function selfTestParamsMode(x3dhFile) {
  const s = x3dhFile.scenarios[0];
  const out = x3dhKdf(
    responderDh({ ikPriv: BOB.ik.priv, spkPriv: BOB.spk.priv, peerIk: ALICE.ik.pub, peerEk: unhex(s.x3dh.ek_public_hex) }),
    PARAMS.x3dh.kdf,
  );
  return hex(out.sk) === s.x3dh.sk_hex ? [] : ['--params path with v2 parameters does not reproduce no_opk SK'];
}

// ---------------------------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------------------------

const toJson = (o) => `${JSON.stringify(o, null, 2)}\n`;

function selfCheck({ alsoDisk }) {
  const failures = [...selfTestInternals(), ...verifyPrimitives(PUBLISHED).map((f) => `in-file transcription: ${f}`)];
  if (alsoDisk) {
    const p = path.join(VECTORS_DIR, 'primitives.json');
    if (!fs.existsSync(p)) failures.push('vectors/primitives.json is missing');
    else {
      let disk;
      try {
        disk = JSON.parse(fs.readFileSync(p, 'utf8'));
      } catch (e) {
        failures.push(`vectors/primitives.json does not parse (${e.message})`);
      }
      if (disk) failures.push(...verifyPrimitives(disk).map((f) => `vectors/primitives.json: ${f}`));
    }
  }
  return failures;
}

function buildAll() {
  const primitives = buildPrimitivesObject();
  const primitivesFailures = verifyPrimitives(JSON.parse(toJson(primitives)));
  if (primitivesFailures.length) fail(`generated primitives.json fails its own check: ${primitivesFailures.join('; ')}`);
  const x3dh = buildX3dhFile();
  const paramFailures = selfTestParamsMode(x3dh);
  if (paramFailures.length) fail(paramFailures.join('; '));
  return new Map([
    ['primitives.json', toJson(primitives)],
    ['x3dh-v2.json', toJson(x3dh)],
    ['ratchet-v2.json', toJson(buildRatchetFile())],
    ['aead-edges.json', toJson(buildAeadFile())],
    ['spk-sig-msg-v1-independent.json', toJson(buildSpkSigFile())],
  ]);
}

function main(argv) {
  const mode = argv[0];
  if (mode === '--params') {
    if (!argv[1]) fail('--params needs a file');
    return runParams(argv[1]);
  }
  if (mode !== '--write' && mode !== '--check') {
    process.stderr.write('usage: node scripts/gen-vectors-v2.mjs --write | --check | --params <file.json>\n');
    return 2;
  }
  const failures = selfCheck({ alsoDisk: mode === '--check' });
  if (failures.length) {
    process.stderr.write(`self-check failed; nothing written:\n${failures.map((f) => `  - ${f}`).join('\n')}\n`);
    return 1;
  }
  process.stdout.write('self-check: every published primitive matches (node:crypto and second derivations)\n');
  const files = buildAll();
  if (mode === '--write') {
    fs.mkdirSync(VECTORS_DIR, { recursive: true });
    for (const [name, text] of files) fs.writeFileSync(path.join(VECTORS_DIR, name), text);
    for (const name of files.keys()) process.stdout.write(`wrote vectors/${name}\n`);
    return 0;
  }
  let same = true;
  for (const [name, text] of files) {
    const p = path.join(VECTORS_DIR, name);
    const ok = fs.existsSync(p) && fs.readFileSync(p).equals(Buffer.from(text, 'utf8'));
    if (!ok) same = false;
    process.stdout.write(`${ok ? 'same' : 'DIFFERS'}: vectors/${name}\n`);
  }
  return same ? 0 : 1;
}

try {
  process.exitCode = main(process.argv.slice(2));
} catch (e) {
  process.stderr.write(`gen-vectors-v2: ${e.message}\n`);
  process.exitCode = 1;
}

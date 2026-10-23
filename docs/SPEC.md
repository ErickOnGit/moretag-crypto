# moretag-crypto protocol v2 (package 3.x)

This is the normative description of what the library computes and stores. The
code and the vectors in `vectors/` must agree with it byte for byte.

**What it is.** X3DH and the Double Ratchet as specified by Signal (revision 1,
2016), with documented deviations: a separate Ed25519 signing key in place of
XEdDSA; a signed-prekey signature over a CBOR array of device id, identity key,
signed prekey and id; XChaCha20-Poly1305 with a random nonce; an HKDF chain KDF;
Ed25519 keys and device ids appended to the associated data. It is not
interoperable with any other implementation, and claims no equivalence with one.

**Sources.** X3DH revision 1 (2016-11-04) and the Double Ratchet revision 1
(2016-11-20). Section numbers below are revision 1's. signal.org now serves the
Double Ratchet's revision 4, whose classical sections 3.1 to 3.5 match revision 1;
revision 4 moved "recommended cryptographic algorithms" from §5.2 to §7.2. Also
RFC 7748 (X25519), RFC 8032 (Ed25519), RFC 5869 (HKDF), draft-irtf-cfrg-xchacha-03
(XChaCha20-Poly1305) and RFC 8949 (CBOR).

**Marks.** [spec] as specified; [option] a choice the specifications allow;
[deviation] a documented deviation.

## 1. Versions

Protocol v2 replaces v1 entirely. There is no dual-version code and no migration
of stored v1 state: v1 sessions, prekey records and stored files are refused, and
the host resets its devices (see `docs/VERSION_MIGRATION.md`).

| Item | v1 | v2 |
|---|---|---|
| X3DH info | `moretag/x3dh/v1` | `moretag/x3dh/v2` |
| Root, chain info | `moretag/v1/rkck`, `moretag/v1/ckmk` | `moretag/v2/rkck`, `moretag/v2/ckmk` |
| X3DH KDF input | DH1 ‖ DH2 ‖ DH3 [‖ DH4] | F ‖ DH1 ‖ DH2 ‖ DH3 [‖ DH4] |
| Message AAD | CBOR map of the header | AD (164 bytes) ‖ H (CBOR array with `grp`) |
| Ratchet init | EK reused as the first sending key | RatchetInitAlice / RatchetInitBob (DR §3.3) |
| Header `v`, device ids | 1, any string | 2, canonical UUID; optional `grp {gid, epoch}` |
| `session_init` | v 1; Ed25519 key optional; ids number or string | v 2; `sender_ik_sig_pub_b64` required; ids integers 1 to 2^31−1; `opk_id` present exactly when `used_opk` |
| Bundle | v 1; the device's own bundle offered a one-time prekey | v 2; one-time prekey optional, served by the server |
| Ratchet state | version 1 | version 2: `role`, `ad`, optional remote key |
| Prekey-manager state | ids number or string | version 2, numeric ids, `next_opk_id` above every id |
| Names whose bytes change | `…V1` | `…V2`, no V1 export |
| Package | 2.2.1 | 3.0.0 |
| Alg strings, signed-prekey signature | — | unchanged |

Removed with no replacement: `allowLegacyFormat` (the 2.1.x file-store format),
`sealArchiveV1`, `openArchiveV1`, `ArchiveHeaderV1`, `encodeAADFromHeaderV1`,
`ratchetInit`, `advanceDh` and the lazy sending step, `addOneTimePrekeys` with an
arbitrary start id, `consumeOneTimePrekey`, the v1 trust wrappers.

## 2. Primitives and parameters

| Use | Choice | Mark |
|---|---|---|
| Curve, hash | X25519 and SHA-256 (X3DH §2.1) | [spec] |
| Identity | X25519 key IK for DH, separate Ed25519 key IKsig for signatures | [deviation] |
| All-zero DH output | refused, checked by OR-accumulating every byte (RFC 7748 §6.1) | [option] |
| X3DH KDF | HKDF-SHA256, salt 32 zero bytes, info `moretag/x3dh/v2`, 32-byte SK (X3DH §2.2) | [spec] |
| KDF_RK | HKDF-SHA256(salt = RK, ikm = DH output, info `moretag/v2/rkck`, 64), split 32 root key / 32 chain key (DR §5.2) | [spec] |
| KDF_CK | HKDF-SHA256(salt = empty, ikm = CK, info `moretag/v2/ckmk`, 64), split 32 chain key / 32 message key | [option] (DR §5.2 recommends HMAC) |
| AEAD | XChaCha20-Poly1305 under the message key, random 24-byte nonce carried in the header (DR §3.1) | [option] |
| Associated data | AD (§5) ‖ H (§6.2), the Double Ratchet's CONCAT(AD, header) (DR §3.1, §3.4) | [spec] |
| Header encryption | none (DR §4) | [option] |
| MAX_SKIP | a single gap over 1,000 is `skip_limit_exceeded` (DR §3.5); the cache keeps 2,000 by evicting the oldest | [option] |
| Base64 | standard alphabet, padded, canonical: non-zero padding bits are refused | — |
| CBOR | shortest form (RFC 8949 §4.2.1), byte strings untagged, integers of 2^32 and above as integers | — |

## 3. Device ids

A device id is a canonical UUID string: lowercase hex in the 8-4-4-4-12 layout,
as Postgres prints a `uuid`. Version and variant bits are not checked. Every v2
validator (header, `session_init`, bundle, associated data) refuses anything else
with `invalid_device_id`. Inside AD and H a device id is its 16 raw bytes; inside
a signed or self-seal CBOR array it is the text string. Both ends of a session
must be different devices (`self_session`) [deviation: a host rule].

## 4. X3DH

### 4.1 Keys and signatures

Each device holds IK (X25519) and IKsig (Ed25519, RFC 8032), signed prekeys
(X25519, id 1..2^31−1) and one-time prekeys (X25519, id 1..2^31−1). IKsig signs
two messages, each a CBOR array that begins with its own domain string, so a
signature for one purpose never verifies for another (the library's
signing-domain test checks this):

- **Signed prekey** (unchanged since v1; the string names the signature format,
  not the protocol): `["moretag/x3dh/spk/v1", device_id, IK (bstr 32), SPK (bstr 32), spk_id]`.
  [deviation] (X3DH §3.2 signs `Encode(SPK)` with XEdDSA.)
- **One-time prekey batch**: `["moretag/x3dh/opk-batch/v1", device_id, [[opk_id, key (bstr 32)], …]]`
  in the order sent. The server verifies it with the device's stored IKsig before
  storing a batch. Golden bytes: `vectors/opk-batch-sig-msg-v1.json`.

A planned device proof (`moretag/device-proof/v1`) follows the same rule.

### 4.2 Key agreement

```
DH1 = DH(IK_A, SPK_B)    DH2 = DH(EK_A, IK_B)    DH3 = DH(EK_A, SPK_B)
DH4 = DH(EK_A, OPK_B)    only when the bundle carried a one-time prekey
KM  = F || DH1 || DH2 || DH3 [|| DH4]            128 or 160 bytes
F   = 32 bytes of 0xFF
SK  = HKDF-SHA256(salt = 32 zero bytes, ikm = KM, info = "moretag/x3dh/v2", L = 32)
```

[spec] (X3DH §2.2, §3.3). X3DH §2.2 defines F as "used for cryptographic domain
separation with XEdDSA": XEdDSA hashes with `hash_i(X) = hash(2^b − 1 − i || X)`
for i ≥ 1, and 32 bytes of 0xFF is the i = 0 prefix, so where one key both signs
and does DH no X3DH KDF input begins like an XEdDSA hash input. Our X25519 key
never signs, so that purpose does not apply: **F has no security purpose here**.
It is included so the KDF input matches the specification, and nothing more is
claimed for it.

### 4.3 The initiator

`x3dhInitiatorBootstrapV2` runs in X3DH §3.3's order:

1. Check the bundle's shape (`invalid_bundle`, `invalid_device_id`).
2. Verify the signed-prekey signature with the bundle's IKsig (`bad_signature`).
3. Check that the bundle names the device the host asked for (`device_mismatch`).
4. Check and pin the recipient's two identity keys (`IdentityRegistry.assertOrPin`,
   `identity_mismatch` on a changed identity). Nothing is pinned before step 3.
5. Draw EK, compute DH1–DH4 and SK, build AD, wipe EK.
6. RatchetInitAlice (§6.1), which draws the first DHs.

It returns the ratchet state and the `session_init` sidecar. The initiator's
Ed25519 key is required and enters AD. EK's private key never leaves the library.

### 4.4 The responder

`x3dhResponderBootstrapV2` runs in memory and consumes nothing:

1. Check the sidecar's shape (`invalid_session_init`, `invalid_device_id`).
2. Equal devices are `self_session`. The sidecar's sender must equal the
   `sender_device_id` the host passes, taken from the server row, never from the
   sidecar; its recipient must be this device (`device_mismatch`).
3. Read the signed prekey and, when `used_opk`, the one-time prekey, without
   consuming them (`unknown_spk`, `unknown_opk`).
4. Compute DH1–DH4 and SK, build AD, RatchetInitBob (§6.1). No draw. It takes no
   trust registry: the host checks and pins only after a message authenticates.

It returns the state and `used: { spk_id, opk_id? }`. The first message's
successful decrypt binds every security-relevant sidecar field: EK, `spk_id` and
`opk_id` through SK; the keys and device ids through AD.

**X3DH §4.3.** The responder's first decrypt runs the DH step, which draws a
fresh DHs before it ever sends. So two bootstraps from one setup (a replayed first
message, two tabs) reply with different ratchet keys and ciphertexts. A test
checks this.

## 5. Associated data

Built once at bootstrap from decoded bytes; A is the initiator and B the responder
for the whole session, in both directions:

```
AD = 0x05 || IK_A      (33)
  || 0x05 || IK_B      (33)
  || 0xED || IKsig_A   (33)
  || 0xED || IKsig_B   (33)
  || dev_A             (16)   raw bytes of the UUID
  || dev_B             (16)
                       = 164 bytes, fixed
```

The first 66 bytes are X3DH §3.3's `Encode(IK_A) || Encode(IK_B)` with §2.1's
curve-type byte; 0x05 is our choice [option] and no byte parity with anything
else is claimed. The Ed25519 keys and device ids are the "additional information"
§3.3 allows to be appended [option]: no DH covers the Ed25519 keys, and the device
ids stop a valid setup being relabelled as another device. 0xED is our constant.
No account ids: a guest-to-member merge changes the user id; account binding
belongs to safety numbers. The length is fixed, so CONCAT(AD, H) needs no length
prefix. `parseAssociatedDataV2` splits it back for checks.

## 6. The Double Ratchet

### 6.1 Initialization (DR §3.3)

- **Initiator** (`ratchetInitInitiatorV2`): a fresh DHs (one 32-byte draw),
  DHr = SPK_B, `RK, CKs = KDF_RK(SK, DH(DHs, SPK_B))`, no CKr. [spec]
- **Responder** (`ratchetInitResponderV2`): DHs = a copy of the signed-prekey
  pair, no DHr, RK = SK, no chains. [spec] Its first received message runs the DH
  step.

Both copy every input; a state never aliases a caller's or the prekey manager's
arrays. The state's `role` fixes which AD device is its own.

### 6.2 Messages

**Encrypt** (`ratchetEncrypt`): requires CKs (`no_sending_chain` otherwise; there
is no lazy sending step). `CKs, mk = KDF_CK(CKs)`, one 24-byte nonce draw, the
header's device ids from AD by role (sender = this state's own device), AAD =
AD ‖ H, then `Ns += 1`.

**The header on the wire** is a JSON object:

```jsonc
{
  "v": 2,
  "alg": "xchacha20poly1305",
  "nonce_b64": "<base64, 24 bytes>",
  "sender_device_id": "<canonical UUID>",
  "recipient_device_id": "<canonical UUID>",
  "dr": { "dh_pub_b64": "<base64, 32 bytes>", "pn": <uint>, "n": <uint> },
  "grp": { "gid": "<canonical UUID>", "epoch": <safe integer >= 0> }   // group messages only
}
```

Other keys (a host's `session_init` sidecar) may ride in the same object; they
never enter the AAD.

**H**, the header half of the AAD, is one shortest-form CBOR array built from the
decoded fields:

```
H = [2, "xchacha20poly1305", nonce (bstr 24), dev_sender (bstr 16), dev_recipient (bstr 16),
     dh_pub (bstr 32), pn (uint), n (uint), grp]
grp = null                                  pairwise message
    | [gid (bstr 16), epoch (uint)]         group message
```

**The group slot** applies the decision to put a group id and membership epoch in
the wire format now. The library checks its shape (`invalid_grp`), authenticates
it in H and returns it from `ratchetDecrypt`. Pairwise messages leave it out (H
carries null). When groups exist, the host's duty is to check `gid` against the
row's conversation and `epoch` against the server's membership epoch; that duty,
and where the epoch lives, belong to the group design.

**Decrypt** (`ratchetDecrypt`) works on a copy and changes the caller's state only
on success. Order:

1. Check the header (`invalid_header`, `invalid_device_id`, `invalid_grp`).
2. Its ids must be the peer's (sender) and this device's (recipient) as AD names
   them (`device_mismatch`), before any key derivation or AEAD. Then the
   ciphertext must be strict base64 of at most 1,100,000 bytes (`invalid_header`,
   field `ciphertext_b64`).
3. A stored skipped key for (dh_pub, n): decrypt with it and delete it.
4. Otherwise, on the current receiving chain (dh_pub = DHr, CKr present), `n < Nr`
   is `replay_detected`, before any key derivation or AEAD.
5. Otherwise, when dh_pub differs from DHr or DHr is absent: store the old chain's
   skipped keys up to `pn` (`skip_limit_exceeded` past MAX_SKIP), then the DH
   step (DR §3.4): `PN = Ns; Ns = Nr = 0; DHr = dh_pub;
   RK, CKr = KDF_RK(RK, DH(DHs, DHr))`; a fresh DHs (one 32-byte draw);
   `RK, CKs = KDF_RK(RK, DH(DHs, DHr))`.
6. Store skipped keys up to `n` (`skip_limit_exceeded` past MAX_SKIP). With no
   CKr (dh_pub = DHr on an initiator before the first reply, which only a forged
   header naming the responder's signed prekey reaches) the message cannot be
   authentic: `decrypt_failed`. Otherwise step CKr for the message key, AEAD under
   AD ‖ H (`decrypt_failed`).

**Skipped keys.** Keyed `base64(dh_pub):n`. A single gap over 1,000 is
`skip_limit_exceeded`.
At 2,000 the oldest key is evicted (and wiped), so a long gap costs the oldest
missing messages rather than refusing every later one; an evicted message is then
`replay_detected` on the current chain or `decrypt_failed` on an earlier one.

**Replays.** `replay_detected` covers the current receiving chain only. A replay
from an earlier chain fails the AEAD (`decrypt_failed`). Nothing here survives the
loss or rollback of stored state: this is not a persistent replay cache.

## 7. Random draws (normative)

1. `x3dhInitiatorBootstrapV2`: EK private (32), then `DHs` private (32).
2. `x3dhResponderBootstrapV2`, `ratchetInitResponderV2`: none.
3. `ratchetEncrypt`: one 24-byte nonce.
4. `ratchetDecrypt` when `dh_pub` differs from `DHr` or `DHr` is absent: after storing the old chain's skipped keys and stepping the receiving chain, one 32-byte `DHs` private; then the message key and the AEAD. No draw otherwise. On a failed AEAD the draw is discarded with the clone.
5. Prekey manager: one 32-byte draw per one-time prekey in id order; one per SPK rotation.
6. `sealLocalV2`: one 24-byte nonce.
7. The `registerCryptoPrimitives` self-test draws before any vector queue starts.

The prekey manager's creation draws the X25519 identity key, then the Ed25519
seed, then signed prekey 1, then its one-time prekeys in id order. X25519 private
keys the library generates are stored clamped; X25519 clamps inside, so a raw
draw and its clamped form give the same key.

## 8. Wire objects

### 8.1 Prekey bundle (`X3DHPrekeyBundleV2`)

```jsonc
{
  "v": 2,
  "alg": "x3dh-x25519-hkdf-sha256+ed25519",
  "recipient_device_id": "<canonical UUID>",
  "ik_pub_b64": "<X25519, 32 bytes>",
  "ik_sig_pub_b64": "<Ed25519, 32 bytes>",
  "spk_pub_b64": "<X25519, 32 bytes>",
  "spk_id": <1..2^31-1>,
  "spk_sig_b64": "<Ed25519 signature, 64 bytes>",
  "opk_id": <1..2^31-1>,          // together with opk_pub_b64, or neither
  "opk_pub_b64": "<X25519, 32 bytes>"
}
```

The device publishes the bundle without a one-time prekey; the server allocates
one per bundle it serves and adds `opk_id` (the device's local id) and
`opk_pub_b64`, or leaves both out when the pool is empty or a limit is reached.

### 8.2 Session init (`X3DHSessionInitV2`)

```jsonc
{
  "v": 2,
  "alg": "x3dh-x25519-hkdf-sha256+ed25519",
  "sender_device_id": "<canonical UUID>",
  "recipient_device_id": "<canonical UUID>",
  "sender_ik_pub_b64": "<X25519, 32 bytes>",
  "sender_ik_sig_pub_b64": "<Ed25519, 32 bytes>",   // required
  "ek_pub_b64": "<X25519, 32 bytes>",
  "spk_id": <1..2^31-1>,
  "used_opk": <boolean>,
  "opk_id": <1..2^31-1>          // present exactly when used_opk
}
```

All validators decode strict base64 and check exact lengths; a refusal names the
field, never its value.

## 9. State formats

**Ratchet state** (`SerializedRatchetStateV2`, JSON):
`{ v: 2, role: "initiator" | "responder", ad_b64, rk32_b64, ck_s32_b64 | null, ck_r32_b64 | null, ns, nr, pn, dh_self: { priv32_b64, pub32_b64 }, dh_remote_pub32_b64 | null, skipped: [[ "base64(dh_pub):n", mk32_b64 ], …] }`,
skipped oldest first. **Persisted session** (`SerializedPersistedSessionV2`):
`{ v: 2, version, state }`, `version` the store's optimistic counter.

**Prekey manager** (`X3DHPrekeyManagerStateV2`):
`{ v: 2, recipient_device_id, ik_x25519_priv_b64, ik_x25519_pub_b64, ik_ed25519_priv_b64, ik_ed25519_pub_b64, current_spk_id | null, spks: [{ spk_id, priv32_b64, pub32_b64, created_at_ms }], opks: [{ opk_id, … }], next_opk_id }`.
Ids are never reused: `mintOneTimePrekeys(count, minNextId)` starts at
max(`next_opk_id`, `minNextId`), and a host passes the server's high-water mark + 1.
A signed prekey rotates only to a higher id. Reading a one-time prekey does not
consume it; `removeOneTimePrekey` (idempotent) does.

Every deserializer treats stored state as untrusted input and checks every field
(version, role, a well-formed AD, 32-byte keys, null or 32-byte optional keys,
non-negative safe-integer counters, at most 2,000 skipped keys with well-formed,
unique ids; for prekeys: canonical device id, ids in range and unique, a current
signed prekey that exists, `next_opk_id` above every id). A refusal reads
"Corrupt session state: <field>" or "Corrupt prekey state: <field>" and never
contains the stored value.

## 10. Local seals

`sealLocalV2({ key32, aad, plaintext })` is XChaCha20-Poly1305 under a caller key,
a fresh random 24-byte nonce (one draw) and caller AAD; it returns `nonce_b64`
and `ciphertext_b64`. No ratchet is involved. `buildSelfSealAadV2(device_id)`
gives the AAD a host uses for its own copy of what it sent:
CBOR `["moretag/self/v1", device_id]`. [deviation: host design]

## 11. Errors

Every typed error has a stable `code`; messages carry no caller-supplied
identifier and no stored value. Hosts log `name` and `code`, not the message.

| Class | `code` | Raised when | State changed? |
|---|---|---|---|
| `ReplayDetectedError` | `replay_detected` | a message on the current receiving chain whose key is already used | no |
| `DecryptFailedError` | `decrypt_failed` | the AEAD refuses (wrong key, AD, header, ciphertext; an earlier-chain replay); a header on the current ratchet key when there is no receiving chain yet (an initiator before the first reply, sent the responder's public signed prekey as `dh_pub`), which no real message does | no |
| `UnknownPrekeyError` | `unknown_spk`, `unknown_opk` | a setup names a prekey this device does not hold | no |
| `DeviceMismatchError` | `device_mismatch` | a bundle for another device; a sidecar whose sender differs from the row or whose recipient is not this device; header ids differing from AD | no |
| `SelfSessionError` | `self_session` | both ends would be the same device | no |
| `NoSendingChainError` | `no_sending_chain` | encrypt on a responder state before its first received message | no |
| `SkipLimitError` | `skip_limit_exceeded` | a header's `n`, or its `pn` before a DH step, more than MAX_SKIP (1,000) past the receiving chain's next number; raised before the AEAD, so a peer or the server can cause it | no |
| `InvalidDeviceIdError` | `invalid_device_id` | a device id that is not a canonical UUID | no |
| `InvalidWireError` | `invalid_header`, `invalid_grp`, `invalid_session_init`, `invalid_bundle` | a wire object with the wrong shape, base64, length or id range; a message's `ciphertext_b64` that is not strict base64 or decodes to more than 1,100,000 bytes (`invalid_header`, field `ciphertext_b64`) | no |
| `BadSignatureError` | `bad_signature` | a bundle's signed-prekey signature does not verify | no; nothing pinned |
| `LowOrderKeyError` | `low_order_key` | an X25519 agreement gives the all-zero output (a low-order public key) | no |
| `IdentityMismatchError` | `identity_mismatch` | a pinned device presents other identity keys; the registry records the block | the registry's block mark only |
| `SessionNotFoundError` | `session_not_found` | a store has no session under the id | no |
| `RatchetStoreConflictError` | `store_conflict` | an optimistic store update lost a race | no |

`low_order_key`, `bad_signature`, `invalid_grp`, `invalid_session_init`,
`invalid_header`, `invalid_bundle` and `skip_limit_exceeded` are the library's own
codes for refusals the design named no code for; the vector tests map them. Every
refusal a peer or the server can cause through a header, a sidecar, a bundle or a
ciphertext is typed. Not typed, because only the host's own data or code can cause
them: corrupt stored state (TypeError, above), a caller's key of the wrong length,
and a plaintext over the encrypt limit (TypeError).

## 12. What the host must do

The library computes; the host owns ordering, storage and policy. moreTag's app
does the following.

- **Row-bound peer device.** Pass the server row's sender device as
  `sender_device_id`; a header or sidecar sender that differs is
  `device_mismatch`, before any crypto, with nothing saved.
- **Init until reply.** Send `session_init` beside every message until a peer
  message decrypts on that session, so any first message can set the session up.
- **First message, in this order.** If the setup's EK and `opk_id` match a stored
  state's `bootstrap_ek` / `bootstrap_opk_id`, decrypt there as a normal message.
  Otherwise bootstrap in memory, trial-decrypt, then `IdentityRegistry.check`
  (a mismatch saves only the block and holds the one-time prekey). Then commit
  under the prekey lock (pair lock outside, prekey lock inside): re-read the
  prekey record and the pair's session records from storage; if a stored record
  already names this setup, refuse `replay_detected` (another tab or run accepted
  it) and save nothing; if the one-time or signed prekey is gone, refuse
  `unknown_opk` / `unknown_spk`; pin; save the post-decrypt state with
  `bootstrap_ek` and `bootstrap_opk_id`; then `removeOneTimePrekey` and save the
  prekey record; then update caches.
- **Crash ordering.** The session is saved before the one-time prekey is deleted,
  so a crash cannot lose the message. A crash between the two leaves a key a
  session record names; a finishing step deletes, idempotently, every one-time
  prekey any stored record names, on prekey-record load, during maintenance, on a
  message for that session, and before any reset that removes such a record.
- **Session placement** (the design's §4.5 recommendation, pending Erick's
  decision 3). Per pair, a `current` state and at most one `previous`. A new setup
  that decrypts becomes `current` and the old `current` becomes `previous` (an
  older `previous` is dropped). A message without a setup tries `current`, then
  `previous`, picked by `dh_pub` (at most two AEAD attempts); only the state that
  decrypts is saved. A message that decrypts on `previous` swaps the two, unless
  `previous` is marked `expired`. Expiry moves `current` to `previous` with
  `expired: true`: it still reads in-flight peer messages and is never promoted.
  `previous` is dropped 7 days after it took the slot, on a reset, on sign-out, or
  when another state takes the slot. Cost: for up to 7 days the previous state
  keeps keys that can read messages the peer sent on it.
  **Strict alternative** (if decision 3 stays "one record per pair"): a new setup
  that decrypts replaces `current` and nothing is kept. Losses: in a simultaneous
  start, the messages each side sent before seeing the other's setup; across an
  expiry or a peer's reset, the peer's messages in flight; a simultaneous start
  can leave both sides on different sessions until one person resets.
- **Self copies.** No session with the device's own id (`self_session`). The own
  copy of a sent message is a local seal (§10) under a 32-byte key kept in the
  prekey record.
- **Prekey maintenance.** Publish signed batches of one-time prekeys minted above
  the server's high-water mark; rotate the signed prekey to a higher id; remove a
  replaced signed prekey 30 days after the server confirms its successor; delete
  a one-time prekey the server handed out but no message used 30 days after the
  device first sees it allocated.
- **No backup of private crypto state.** None exists and none may be added: a
  restored backup would bring back deleted one-time prekeys and roll ratchets
  back. Android sets `allowBackup` false.
- **Groups.** Check `grp` as §6.2 says, once groups exist.

## 13. Residuals

**The fallback** (pending Erick's decision 2; this is the design's recommended
text). When the server serves no one-time prekey (pool empty, a limit reached, or
a hostile server withholding it, X3DH §4.7), the initiator runs DH1–DH3 with
`used_opk: false` (X3DH §3.3). First-message forward secrecy then rests on the
identity key and the signed prekey (rotated every 7 days, kept 30 days after its
successor is confirmed), and a replayed setup is accepted after a reset.

**Replay after a reset.** Without a reset, a replayed setup is a known setup and
its messages are ratchet replays (`replay_detected`).

| Setup used a one-time prekey? | Replayed setup after a reset or lost state | Old message shown again? | Session rolled back? |
|---|---|---|---|
| Yes | refused (`unknown_opk`, nothing saved), in every tab | no | no |
| No (fallback) | accepted again (the replay cache is paused) | yes, until a reply | yes; the two sides fall out of step until one resets |

A same-device encrypted iOS backup restore of keychain and app data brings
deleted keys back until the app's storage change sets a keychain class that
excludes backups.

## 14. Storage invariants

- `FileRatchetStore` (Node only) requires a 32-byte MAC key. A session file is
  `{ v: 2, payload, mac_b64 }`, `payload` the persisted session in §9's form and
  `mac_b64 = HMAC-SHA256(macKey32, "moretag-crypto/file-store/session/v2" || 0x00 || sessionId || 0x00 || JSON(payload))`.
  The rollback counter is `{ v: 2, version, mac_b64 }` with
  `mac_b64 = HMAC-SHA256(macKey32, "moretag-crypto/file-store/counter/v2" || 0x00 || sessionId || 0x00 || decimal(version))`.
  A file without `v: 2`, a failed MAC, a malformed or missing counter, or a
  version behind the counter makes load fail; saves never regress the version.
  Writes are temp file, fsync, rename, under a lock file.
- `RatchetSessionStore.transact` is atomic per session id; a missing id is
  `session_not_found` without calling the callback; a throwing callback persists
  nothing; the store persists exactly the returned record.
- Stored state is checked on every load (§9).
- **Zeroing** (best effort). The library wipes the secret arrays it creates: DH
  outputs and the X3DH key material, the ephemeral private key, clamped scalar
  copies, split HKDF outputs, message keys, evicted skipped keys, the root and
  chain keys a decrypt replaces in its working copy, and the whole working copy
  when a decrypt fails. It never wipes an array received from a caller or a
  store. JavaScript promises nothing about copies an engine or provider keeps, so
  this shortens how long a secret stays in memory; it does not prove it is gone.

## 15. Identity model

Each device has two independent identity keys: IK (X25519, DH only) and IKsig
(Ed25519, signatures only). IKsig signs the signed-prekey message, so it vouches
for the device id, IK and the signed prekey; the binding runs one way. Nothing
proves possession of IK's private key, and nothing proves the initiator holds the
IKsig it presents.

What stops a copied identity: unique identity keys on the server (one IK under one
device id); AD in every AEAD carrying both X25519 keys, both Ed25519 keys and both
device ids, so a setup computed for one identity or device fails under another
(unknown-key share, X3DH §4.8); the initiator's Ed25519 key required and bound by
AD; the responder's peer device taken from the server row; verification before
pinning.

| Stolen | What the attacker gains | With one XEdDSA key instead | Residual |
|---|---|---|---|
| IK alone | Can initiate as the victim to anyone (DH1, DH2) and present the victim's public IKsig, since nothing proves possession of it. Cannot act as responder (cannot sign a new signed prekey; the published one needs its private key). No key-compromise impersonation against the victim. No past sessions | Could also sign signed prekeys, so also responder | Impersonation of the victim to others until the device is removed |
| IKsig alone | No confidentiality (a forged signed prekey still needs IK for DH2). Full control-plane authority: it signs signed prekeys, one-time prekey batches and future device proofs | Same key; total either way | A concentration of risk that device proofs must cover |
| A signed prekey (current, or one retained 30 to 37 days) | Key-compromise impersonation against the victim on setups naming that id; with IK, reads first messages sent without a one-time prekey on that key | Same | 30 to 37 days after rotation |
| A one-time prekey alone | Nothing; deleting it after use keeps a first message unreadable after a later full compromise | Same | — |
| The whole device | Everything | Same | Both identity keys share one storage class |

The separate signing key is no weaker than XEdDSA for confidentiality, and
responder impersonation is harder. IKsig's control-plane role is a concentration
of risk, also stated in `docs/THREAT_MODEL.md`.

## 16. Not in v2

- PQXDH or any post-quantum key agreement, and post-quantum ratcheting.
- Header encryption (DR §4).
- Proof of possession of the X25519 identity key, and of the initiator's Ed25519
  key (a check of a setup's keys against the server's registered keys closes the
  second).
- A single XEdDSA key for both DH and signatures.
- A persistent replay cache (paused).
- Account ids in AD (account binding belongs to safety numbers).
- A conversation binding (a hostile server moving a ciphertext between two
  conversations of the same device pair); a binding must allow for account merges.
- A signed `session_init`.
- Groups beyond the authenticated `grp` slot.

## 17. Parameters compared with other implementations

Dated 2026-10-22. "Same" only for what a run proved; everything else is compared
at the primitive level (RFC and draft vectors in `vectors/primitives.json`).

| Source | What was compared | Outcome |
|---|---|---|
| RFC 7748 §5.2 and §6.1; RFC 8032 §7.1 tests 1–3; RFC 5869 A.1–A.3; draft-irtf-cfrg-xchacha-03 §2.2.1 and A.3.1 | every primitive, on @noble and on node:crypto through the adapter | same |
| signalapp/libsignal, tag v0.20.0, commit ab29fed4db04a5335f8a0d1ea03b7a83b93776d2 (2022-08-22, before PQXDH), `rust/protocol/tests/ratchet.rs`, tests `test_ratcheting_session_as_bob` and `test_ratcheting_session_as_alice`; read from the source on the web, nothing cloned or built | the vector generator's X3DH KDF code path in its parameter mode (info `WhisperText`, no salt, F, 64-byte output split 32/32) on the tests' inputs: it reproduced Bob's expected sender chain key and Alice's expected receiver chain key; the same run without F matched neither | **same** for F, the DH1–DH3 pairings and order, the salt (absent = 32 zero bytes), HKDF-SHA256 and the 32/32 split; **not compared** for DH4 (neither test uses a one-time prekey) and the root step (neither test asserts a key from it). Our own info strings, SK length and RatchetInitAlice differ by design (§2). No libsignal constant is in this repository |

## 18. Test vectors

- `vectors/primitives.json`, `x3dh-v2.json`, `ratchet-v2.json`,
  `aead-edges.json`, `spk-sig-msg-v1-independent.json`: written by
  `scripts/gen-vectors-v2.mjs`, whose author read no library source at any tag
  and worked from the design and the public texts only. The generator imports only
  `node:crypto`, `node:fs` and `node:path`; `npm run vectors:check` regenerates
  every file in memory and compares it byte for byte (part of `verify` and CI).
  The files' JSON field names, role names and skipped-key layout are the author's
  own; the tests map them. Only the bytes that enter a KDF, a signature or an AEAD
  are normative.
- `vectors/spk-sig-msg-v1.json`: the signed-prekey message, unchanged since v1;
  the app's and the server's golden-vector tests share its bytes.
- `vectors/opk-batch-sig-msg-v1.json`: the one-time prekey batch message and
  signature, for the server's and the app's copies.

The vector tests run through the public API, once per provider, with a scripted
randomness provider (real randomness until registration, then one ordered queue
of copies, an error on a wrong length, a check that the queue ends empty). Every
refusal vector must fail with its code and leave state unchanged.

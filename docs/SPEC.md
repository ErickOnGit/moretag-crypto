# moretag-crypto v1 Specification (Stable Wire + State)

This document freezes the v1 wire formats, AAD encoding rules, and state machine invariants. All future v1.x releases MUST remain backward compatible with this spec. Any breaking change requires v2.

## Versioning Commitment
- Wire formats and AAD encoding described here are stable for v1.x.
- Ratchet header semantics and state invariants are stable for v1.x.
- Storage invariants (version monotonicity, integrity check layout) are stable for v1.x.

## Wire Formats (v1)

### X3DH Prekey Bundle (X3DHPrekeyBundleV1)
```jsonc
{
  "v": 1,
  "alg": "x3dh-x25519-hkdf-sha256+ed25519",
  "recipient_device_id": "<string>",
  "ik_pub_b64": "<base64 X25519 pub, 32B>",
  "spk_pub_b64": "<base64 X25519 pub, 32B>",
  "ik_sig_pub_b64": "<base64 Ed25519 pub, 32B>",
  "spk_sig_b64": "<base64 Ed25519 sig, 64B>",
  "spk_id": "<string|number>",
  "opk_pub_b64": "<optional base64 X25519 pub, 32B>",
  "opk_id": "<required if opk_pub_b64 present>"
}
```
- SPK signature message: CBOR array `["moretag/x3dh/spk/v1", recipient_device_id, ik_pub32, spk_pub32, spk_id]`.

### X3DH Session Init (X3DHSessionInitV1)
```jsonc
{
  "v": 1,
  "alg": "x3dh-x25519-hkdf-sha256+ed25519",
  "sender_device_id": "<string>",
  "sender_ik_pub_b64": "<base64 X25519 pub, 32B>",
  "ek_pub_b64": "<base64 X25519 pub, 32B>",
  "recipient_device_id": "<string>",
  "spk_id": "<string|number>",
  "used_opk": "<boolean>",
  "opk_id": "<string|number, required if used_opk=true>"
}
```

### Delivery Header (HeaderProtoV1)
```jsonc
{
  "v": 1,
  "alg": "xchacha20poly1305",
  "nonce_b64": "<base64 24B>",
  "sender_device_id": "<string>",
  "recipient_device_id": "<string>",
  "dr": {
    "dh_pub_b64": "<base64 32B>",
    "pn": "<number>",
    "n": "<number>"
  }
}
```

### Archive Header (ArchiveHeaderV1)
```jsonc
{
  "v": 1,
  "alg": "xchacha20poly1305",
  "nonce_b64": "<base64 24B>",
  "sender_device_id": "<string>",
  "dr": {
    "dh_pub_b64": "<base64 32B>",
    "pn": "<number>",
    "n": "<number>"
  }
}
```

### AAD Encoding (Deterministic CBOR)
- Canonicalization: for every plain object, sort keys by UTF-8 length first, then bytewise lexicographic. Arrays keep order. Non-plain objects (Uint8Array, Date, etc.) are left as-is.
- CBOR encoder options: `mapsAsObjects=false`, `useRecords=false`.
- AAD for delivery/archive is `CBOR(canonicalized header)`.
- AAD MUST match vectors in `vectors/delivery-aad-v1.json`.

## Ratchet Header Semantics (dr)
- `dr.dh_pub_b64`: current sending DH public key (32B X25519).
- `dr.pn`: previous chain length at last DH ratchet step.
- `dr.n`: message number within current sending chain (0-based).
- These fields are authenticated via AAD; any change breaks decryption.

## Ratchet State Machine (v1)
- State: `{ rk32, ck_s32?, ck_r32?, ns, nr, pn, dh_self{priv32,pub32}, dh_remote_pub32, skipped }`.
- DH step (send): generate new DH, derive `rk32, ck_s32`, set `pn=ns`, reset `ns`.
- Receive DH step: if incoming DH != `dh_remote_pub32`, first derive skipped for old chain up to `pn`, then derive new `rk32, ck_r32` with incoming DH, generate new send DH and derive new `rk32, ck_s32`, set `pn=ns`, reset `ns/nr`.
- Message keys: `kdfChainKey` on `ck_s32`/`ck_r32`; increment `ns`/`nr`.
- Skipped keys: store derived MKs for out-of-order messages keyed by `dh_pub_b64:n`.
- Limits: skipped-key cache <= 2000; receive derivation gap <= 1000; plaintext <= ~1MB; ciphertext <= ~1.1MB. Violations MUST error.
- State must not advance on decrypt failure; state updates occur only after successful decryption.

## Storage Invariants (v1)
- Session records include `version` (monotonic integer) and ratchet state.
- File store persists `version` counter separately; saves must not regress version; loads detect rollback (version < counter).
- Optional HMAC integrity: when enabled, stored JSON is `{ payload, mac_b64 }` where `mac_b64 = HMAC-SHA256(macKey32, JSON(payload))`. Verification MUST be constant-time over MAC bytes.
- Atomicity: writes use temp file + fsync, then rename; lock file guards concurrent access in file store.
- Backward compatibility: stored payload fields and layout are stable for v1.x; new optional fields must be additive.

## Backward Compatibility Rules
- Never change meanings or validation of existing fields in v1.x.
- Only additive, optional fields may be introduced; defaults must preserve existing behavior.
- Do not change AAD canonicalization rules or CBOR encoder options in v1.x.
- Any change to DH/AAD/key-derivation/order requires v2.

## Test Vectors
- Delivery AAD: `vectors/delivery-aad-v1.json`.
- SPK signature message framing: `vectors/spk-sig-msg-v1.json`.
- These vectors MUST continue to pass in v1.x.

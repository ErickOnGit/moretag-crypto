# Double Ratchet MVP Plan (v1)

This repository currently ships X3DH and envelope sealing, but it is missing the Double Ratchet state machine. Below is a concrete plan to add a production-ready ratchet layer compatible with the existing header shapes.

## Scope
- One-to-one sessions, per-device.
- Asynchronous delivery with skipped-message key storage.
- Header wire format stays: `dr = { dh_pub_b64, pn, n }`.
- No attachment/file payload handling yet (payload is opaque bytes).

## State Model
- Root key `rk32`, sending chain `ck_s32`, receiving chain `ck_r32`.
- DH ratchet key pair `(dh_priv32, dh_pub32)`.
- Message numbers `ns` (send), `nr` (recv), previous chain length `pn`.
- Skipped keys: map from `dh_pub_b64 + n` -> `mk32`, bounded (e.g., 2000 entries).
- Rekey on every DH ratchet step; delete old keys after use.

## Algorithms
- Message KDFs: reuse `kdfRootAndChainKey` + `kdfChainKey`.
- Receive path:
  1. If ciphertext header matches a skipped key, consume it and delete.
  2. If sender DH != current, advance DH ratchet:
     - `pn = ns`, reset `ns = 0`, `ck_s32 = undefined`.
     - Run `kdfRootAndChainKey(rk32, dh)` to get new `rk32` + `ck_r32`.
     - Swap roles so `ck_r32` feeds receive, new `ck_s32` created on first send after ratchet.
  3. Derive until `n == header.dr.n`, storing skipped message keys along the way (bounded).
  4. Derive target message key, decrypt, then delete key.
- Send path:
  - If a new DH step is requested, generate new DH keypair, compute DH with last remote DH, update `rk32` + `ck_s32`, set `pn = nr`, reset `ns`.
  - For each message: `({ ck_s32, mk32 } = kdfChainKey(ck_s32)); ns++`.

## Persistence
- Session record per peer device:
  - Identity info (ik pub), last remote DH pub, local DH keypair.
  - `rk32`, `ck_s32`, `ck_r32`, counters (`ns`, `nr`, `pn`), skipped-keys map.
  - Version/alg guards.
- Atomic writes: journal or transactional store; ensure key deletion on success paths.

## API Sketch
```ts
interface RatchetHeaderV1 extends DoubleRatchetHeader {}

interface RatchetState {
  version: 1;
  rk32: Uint8Array;
  ck_s32?: Uint8Array;
  ck_r32?: Uint8Array;
  ns: number;
  nr: number;
  pn: number;
  dh_self: { priv32: Uint8Array; pub32: Uint8Array };
  dh_remote_pub32: Uint8Array;
  skipped: Map<string, Uint8Array>; // key: `${b64(dh)}:${n}`
}

function ratchetInit(params: {
  rk32: Uint8Array;
  selfDh?: { priv32: Uint8Array; pub32: Uint8Array };
  remoteDhPub32: Uint8Array;
}): RatchetState;

function ratchetEncrypt(state: RatchetState, plaintext: Uint8Array): {
  state: RatchetState;
  header: RatchetHeaderV1;
  ciphertext_b64: string;
};

function ratchetDecrypt(state: RatchetState, header: RatchetHeaderV1, ciphertext_b64: string): {
  state: RatchetState;
  plaintext: Uint8Array;
};
```

## Safety Limits
- Max skip cache (e.g., 2000) and per-message derivation window (e.g., 1000) to prevent DoS.
- Reject old `pn/n` that exceed window, fail closed.
- Enforce strict base64 + version/alg checks on headers.

## Testing Plan
- Golden test vectors for DH steps and message key derivations.
- Replay protection: reusing a header must fail after first success.
- Out-of-order delivery with gaps fills skipped cache and later consumes it.
- Large gap triggers failure once limits exceed.
- Serialization round-trips for RatchetState with key deletion on consumption.

## Integration Steps
1) Implement ratchet state + encrypt/decrypt APIs under `src/ratchet/`.
2) Wire into seal/open: derive header AAD from ratchet state, keep dh_pub_b64/n/pn in sync.
3) Add persistence interfaces (pluggable storage) with clear deletion semantics.
4) Publish interop vectors and update README with security caveats and usage.

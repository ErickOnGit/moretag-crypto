# Prekeys: Rotation, Publication and Use (protocol v2)

## Overview

A device publishes two kinds of prekeys (X3DH §3.2):

- **The signed prekey (SPK):** one current key, signed by the identity signing key over CBOR `["moretag/x3dh/spk/v1", device_id, IK, SPK, spk_id]`. It is in every bundle.
- **One-time prekeys (OPK):** a pool the server hands out, one per bundle, each to one initiator. A setup that used one cannot be replayed once the key is deleted, and its first message stays unreadable after a later full compromise.

The bundle a device builds itself (`getPrekeyBundle()`) carries only the signed prekey. The server adds a one-time prekey when it serves a bundle to an initiator, or serves the bundle without one when the pool is empty or a limit is reached.

`X3DHPrekeyManagerV2` holds the keys. The numbers below (7 days, 100, 25, 200, 30 days) are moreTag's policy, set by the app and the server; the library enforces only ids and shapes. Formats are in [SPEC.md](./SPEC.md).

## Ids

- Signed and one-time prekey ids are integers 1..2^31-1 (they fit a Postgres `integer`).
- An id never names two keys. `rotateSignedPrekey` refuses an id at or below a held one. `mintOneTimePrekeys` counts up from `next_opk_id`, which is always above every id the manager has minted.
- The server keeps a high-water mark of the one-time prekey ids it has seen. Mint above it, so an id the server knows (even one whose row it has purged) is never reused:

```typescript
const minted = prekeys.mintOneTimePrekeys(100 - status.unallocated_ids.length, status.high_water + 1);
```

## Signed prekey rotation

```typescript
if (prekeys.shouldRotateSignedPrekey(7 * 24 * 60 * 60 * 1000)) {
  const next = prekeys.getCurrentSignedPrekey().spk_id + 1;
  prekeys.rotateSignedPrekey(next);
  // save the record, then upload the new SPK
}
```

- Rotate every 7 days. The server accepts a higher `spk_id` and refuses an older one, so a stale tab cannot roll it back.
- Keep a replaced signed prekey: setups that named it may still arrive. Its 30-day retention starts when the server confirms the successor, not when it was replaced. Then drop it with `removeSignedPrekey(spk_id)`.
- Retained keys widen the window for key-compromise impersonation on setups that name them (30 to 37 days); see [THREAT_MODEL.md](./THREAT_MODEL.md).

## One-time prekeys

### Publication is additive and signed

Each upload adds keys; it never replaces the pool. Publish only keys the server has not seen, and sign the batch:

```typescript
const batch = prekeys.listOneTimePrekeysAbove(publishedThrough);   // ascending, unpublished
const { prekeys: list, batch_sig_b64 } = prekeys.signOneTimePrekeyBatch(batch.map((k) => k.opk_id));
// upload { prekeys: list, batch_sig_b64 } with the publish call
```

The signature is Ed25519 by the identity signing key over CBOR `["moretag/x3dh/opk-batch/v1", device_id, [[opk_id, key], ...]]`, in the order sent. `vectors/opk-batch-sig-msg-v1.json` holds golden bytes that the server's and the app's copies of the message builder must reproduce. A session token alone therefore cannot add keys under a device.

The server takes a batch all or nothing (at most 100 keys). An id above the high-water mark is inserted; the same id and key again is a no-op; the same id with another key refuses the whole batch (`prekey_id_reused`). After a refusal or skipped ids, drop the batch locally and mint above the high-water mark next time.

### The pool

- Target 100 unallocated keys; refill when fewer than 25 remain, minting `100 - remaining`. The server caps a device at 200 unallocated.
- Read the count from the server's status, not from the local pool: the local pool still holds keys the server has handed out but no first message has used yet.
- Save the minted keys before uploading, outside the prekey lock, then lock again to record what was published. A retry re-sends the same ids and keys.

### Allocation (server)

The server allocates one key per bundle, at random, inside one statement, and marks it with the caller and a request id so a retried request gets the same key. Limits over 24 hours: per caller (members 100, guests 20), per target device 50, per caller and target 10. Over a limit, or with an empty pool, it serves the bundle without a key.

### Use and deletion (responder)

- `x3dhResponderBootstrapV2` reads the one-time prekey a setup names **without consuming it**.
- Delete it with `removeOneTimePrekey(opk_id)` only after the first message on that setup decrypted and the session was saved (the commit order in [SESSION_LIFECYCLE.md](./SESSION_LIFECYCLE.md)). A forged first message must not burn a key.
- A key held because the sender's identity changed (blocked) is deleted when the user rejects the new identity, or 30 days after the block.
- A key the server handed out but no first message used: when a published id disappears from the server's unallocated list, record when that was first seen and delete the private key 30 days later.
- A replayed setup whose key was deleted is refused with `unknown_opk`, in every tab, and nothing is saved.

## The fallback: no one-time prekey

When the bundle has no one-time prekey, the initiator runs X3DH with DH1 to DH3 only and sends `used_opk: false` (X3DH §3.3). Sessions still work. The costs, as the design records them pending Erick's decision 2 (the accepted trade-off text):

- First-message forward secrecy rests on the identity key and the signed prekey (rotated every 7 days, kept 30 days after its successor is confirmed).
- After the receiver resets or loses its state, a replayed fallback setup is accepted again, and its old message is shown again (the replay cache is paused).
- A hostile server can always withhold one-time prekeys and force the fallback (X3DH §4.7).

## Checklist

- [ ] Signed prekey rotated every 7 days to a higher id; replaced ones dropped 30 days after the successor is confirmed.
- [ ] One-time prekeys minted above the server's high-water mark, saved before upload, published in signed, additive batches.
- [ ] Refill reads the server's count.
- [ ] One-time prekeys deleted only after the first message decrypts; allocated-unused and held keys pruned after 30 days.

## See Also

- [SPEC.md](./SPEC.md): bundle and session_init formats, the signing messages
- [SESSION_LIFECYCLE.md](./SESSION_LIFECYCLE.md): the responder's commit order and the finishing step
- [IDENTITY_PERSISTENCE.md](./IDENTITY_PERSISTENCE.md): storing the prekey record
- [THREAT_MODEL.md](./THREAT_MODEL.md): signed-prekey compromise and the fallback residuals

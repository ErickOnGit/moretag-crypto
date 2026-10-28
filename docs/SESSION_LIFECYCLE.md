# Session Lifecycle (protocol v2)

## Overview

A session is one bidirectional Double Ratchet state per device pair, set up by X3DH. The library gives the pieces: the two bootstraps, `ratchetEncrypt`, `ratchetDecrypt`, the serializers and the stores. The host stores the states, orders the writes, and sets the lifecycle policy (age, expiry, reset).

The exact formats (session_init, the header, the associated data AD, the state) are in [SPEC.md](./SPEC.md). This guide is about the order of operations around them.

Words used here:
- **Initiator (A)** runs X3DH from the peer's prekey bundle and sends first.
- **Responder (B)** receives the first message and its `session_init` sidecar.
- **The server row** is the delivery record the host received from its server. Its sender device is the authority for who sent the message; the sidecar's own claim is checked against it.

## 1. Setting up a session (initiator)

```typescript
import {
  IdentityRegistry,
  X3DHPrekeyManagerV2,
  x3dhInitiatorBootstrapV2,
  ratchetEncrypt,
} from 'moretag-crypto';

const { session_init, ratchet_state } = x3dhInitiatorBootstrapV2({
  sender_device_id: myDeviceId,                  // canonical lowercase UUID
  recipient_bundle: bundle,                      // X3DHPrekeyBundleV2 from the server
  expected_recipient_device_id: theirDeviceId,   // the device you asked the server for
  initiator_ik_priv32: myPrekeys.ik.priv32,
  initiator_ik_sig_pub32: myPrekeys.ik_sig.pub32, // required
  trust,                                         // IdentityRegistry
});

const { header, ciphertext_b64 } = ratchetEncrypt({ state: ratchet_state, plaintext });
```

Inside, in X3DH §3.3's order:
1. The bundle's shape is checked (`invalid_bundle`, `invalid_device_id`).
2. The signed-prekey signature is verified (`bad_signature`).
3. The bundle must name `expected_recipient_device_id` (`device_mismatch`).
4. The recipient's two identity keys are checked and pinned on `trust` (`IdentityMismatchError`, code `identity_mismatch`, on a changed identity). Nothing is pinned when steps 1 to 3 refuse.
5. X3DH runs, then RatchetInitAlice (DR §3.3). Draws: the ephemeral key, then the first sending key. The ephemeral private key is wiped and never returned.

Equal device ids are refused with `self_session`. A host keeps its own copies of what it sends some other way (for example `sealLocalV2` under a device-local key); it never opens a session with itself.

**Send `session_init` until the peer answers.** The host sends the sidecar beside every message it encrypts on this state, until a message from the peer decrypts on it. A message that arrives without its setup cannot be read by a responder that never saw the setup.

## 2. Receiving a first message (responder): the commit order

The responder must not change anything it stores until the message has authenticated. A forged or replayed first message must not burn a one-time prekey, pin an identity or replace a session.

```typescript
import {
  x3dhResponderBootstrapV2,
  ratchetDecrypt,
  UnknownPrekeyError,
} from 'moretag-crypto';

// 1-3: bootstrap in memory. Reads the prekeys, consumes nothing, pins nothing, draws nothing.
const { ratchet_state, used } = x3dhResponderBootstrapV2({
  session_init,
  prekeys,                               // X3DHPrekeyManagerV2 of this device
  recipient_device_id: myDeviceId,
  sender_device_id: row.senderDeviceId,  // from the server row, not the sidecar
});

// 4: trial-decrypt on the in-memory state. A failure throws; nothing is saved.
const { plaintext } = ratchetDecrypt({ state: ratchet_state, header, ciphertext_b64 });

// 5: identity, check only.
const peer = {
  device_id: row.senderDeviceId,
  ik_pub_b64: session_init.sender_ik_pub_b64,
  ik_sig_pub_b64: session_init.sender_ik_sig_pub_b64,
};
const seen = trust.check(peer); // 'match' | 'unknown' | 'mismatch'; records nothing

// 6: commit under the prekey lock (see below).
```

The steps:

1. **Bind to the row.** The sidecar's sender must be the row's sender and its recipient this device (`device_mismatch`). The header's ids must match the session's AD (`device_mismatch`, checked by `ratchetDecrypt` before any key derivation). Nothing is saved.
2. **Known setup.** If the setup's ephemeral key and `opk_id` match a state the host already stores for this pair, decrypt there as a normal message.
3. **Bootstrap in memory** with `x3dhResponderBootstrapV2`. On `unknown_spk` or `unknown_opk`, reload the prekey record from storage once, then refuse. Nothing is saved.
4. **Trial-decrypt** with `ratchetDecrypt`. It works on a copy, so a failure leaves the state as it was.
5. **Identity** with `IdentityRegistry.check`. On `mismatch` the keys are now authenticated: record the block (`assertOrPin` records it and throws), keep the one-time prekey (held for the block), and save nothing else.
6. **Commit**, under the prekey lock (pair lock outside, prekey lock inside):
   1. Re-read the prekey record and the pair's session records from storage, not from caches.
   2. If any stored record already names this setup, another tab or run accepted it: refuse with `replay_detected` and save nothing.
   3. If the one-time prekey or signed prekey is gone, refuse with `unknown_opk` or `unknown_spk` and save nothing.
   4. Pin the identity (`assertOrPin`).
   5. Save the post-decrypt state, with the setup's ephemeral key and `opk_id` beside it so step 2 and 6.2 can recognise the setup.
   6. Delete the one-time prekey (`prekeys.removeOneTimePrekey(used.opk_id)`) and save the prekey record.
   7. Update caches, release the lock.
7. Return the plaintext.

**Crash ordering.** A crash before 6.5 commits nothing; the message retries cleanly. A crash between 6.5 and 6.6 leaves a one-time prekey that a stored session names. A finishing step deletes, idempotently, every one-time prekey id any stored record names. Run it when the prekey record loads, during prekey maintenance, on a message for that session, and before any reset or replacement that removes such a record. Deleting the key before saving the session would lose the message on a crash.

## 3. After setup

```typescript
const pairwise = ratchetEncrypt({ state, plaintext });
const inGroup = ratchetEncrypt({ state, plaintext, grp: { gid, epoch } }); // authenticated group slot

const { plaintext: pt, grp: slot } = ratchetDecrypt({ state, header, ciphertext_b64 });
```

- Both sides use the same state shape and the same AD for both directions. The header's device ids come from AD by role.
- A responder state cannot send until it has decrypted a message (`no_sending_chain`).
- `ratchetDecrypt` is all-or-nothing: it works on a copy and changes `state` only on success.
- The group slot is authenticated and returned. Pairwise messages leave it out and get `null`. When groups exist, the host must check `gid` against the conversation and `epoch` against the server's membership epoch.
- With a store, use `ratchetEncryptWithStore(store, id, { plaintext })` and `ratchetDecryptWithStore(store, id, { header, ciphertext_b64 })`; each success saves the next version.
- Skipped message keys: a single gap over 1,000 is `SkipLimitError` (`skip_limit_exceeded`); the cache keeps 2,000 by dropping the oldest.

## 4. Errors the host meets

Every typed error has a stable `code`. Messages never contain ids or stored values; log `name` and `code`. The full table is in [SPEC.md](./SPEC.md).

| Code | Where | Usual handling |
|---|---|---|
| `replay_detected` | decrypt, commit step 6.2 | Transient. Do not cache the message as lost. |
| `unknown_opk` | responder bootstrap, commit | Do not cache as lost: another tab or run may hold the plaintext. A reset cannot repair it. |
| `unknown_spk` | responder bootstrap, commit | The message cannot be read. |
| `device_mismatch` | bootstraps, decrypt | The message cannot be read; nothing was saved. |
| `decrypt_failed` | decrypt | The message cannot be read on this state. |
| `skip_limit_exceeded` | decrypt | The header claims more than 1,000 missing messages; it is unauthenticated, so treat it like `decrypt_failed`. Nothing was saved. |
| `identity_mismatch` | initiator bootstrap, `assertOrPin` | Blocked until the user accepts the new identity (`approveRotation`). |
| `no_sending_chain` | encrypt | A responder state that has not received yet. |
| `invalid_header`, `invalid_grp`, `invalid_session_init`, `invalid_bundle`, `invalid_device_id` | validators, decrypt (a bad or oversize `ciphertext_b64` is `invalid_header`) | Malformed input; nothing was saved. |
| `bad_signature` | initiator bootstrap | The bundle is forged or corrupt; nothing was pinned. |
| `low_order_key` | X3DH, DH step | A malicious key; nothing was saved. |
| `self_session` | bootstraps, AD | Never open a session with your own device. |

## 5. Placement: current and previous state

The library keeps no index of sessions; the host decides which stored state a message tries. The design's recommendation, pending Erick's decision 3 (one record per pair):

- Per pair, a `current` state and at most one `previous` state. Sends always use `current`.
- A new setup that decrypts becomes `current`; the old `current` becomes `previous`; an older `previous` is dropped.
- A message without a setup tries `current`, then `previous`, picked by its ratchet key (at most two AEAD attempts). Only the state that decrypts is saved.
- A message that decrypts on `previous` swaps the two, unless `previous` is marked expired. This is how two people who start a chat at the same moment converge.
- Expiry moves `current` to `previous`, marked expired: it still reads in-flight messages and is never promoted. The next send bootstraps.
- `previous` is dropped 7 days after it took the slot, on a reset, on sign-out, or when another state takes the slot.

**The strict alternative**, if one record per pair stays: a new setup that decrypts replaces `current` and nothing is kept. That loses, in a simultaneous start, the messages each side sent before seeing the other's setup, and across an expiry or a peer's reset, the peer's messages in flight; a simultaneous start can leave the two sides on different sessions until one resets.

## 6. Lifetime policy

How long a session lives (age, inactivity, message count) is the host's policy;
the library sets no limit. moreTag keeps its existing expiry rule.

Track creation time, last message time and counts beside the state, not inside it: the library's state holds only what the ratchet needs. Expiry follows the placement rule above.

## 7. Ending a session

- **Reset.** Run the finishing step (section 2), then drop the pair's states. The next send bootstraps a new session. Never reuse a dropped state.
- **Identity change.** Never silently accepted: the initiator's bootstrap and `assertOrPin` throw `IdentityMismatchError` and record the block. Accepting the new identity is an explicit user action (`approveRotation`).
- **Device removed.** Drop its states and call `trust.remove(deviceId)`.
- **No backups.** Never back up or restore private crypto state (sessions or prekeys): a restore brings back deleted one-time prekeys and rolls ratchets back, which re-opens replays.

## 8. Testing

- [src/integration.test.ts](../src/integration.test.ts): one-time prekey, X3DH, first decrypt, commit, file store, out-of-order delivery, replays, a replayed setup after its one-time prekey was deleted.
- [src/vectors/](../src/vectors/): the independent vectors through the public API.

## Checklist

- [ ] The responder follows the commit order in section 2, under a prekey lock, with the pair lock outside it.
- [ ] The finishing step runs on load, maintenance, a message for that session, and before any reset.
- [ ] `session_init` rides every send until a peer message decrypts.
- [ ] The sender device comes from the server row.
- [ ] Logs carry error `name` and `code` only.
- [ ] A placement rule is chosen (section 5) and expiry follows it.
- [ ] No backup of private crypto state.

## See Also

- [SPEC.md](./SPEC.md): formats, draws, errors, storage invariants
- [SESSION_ID_GUIDELINES.md](./SESSION_ID_GUIDELINES.md): storage ids for session records
- [PREKEY_ROTATION.md](./PREKEY_ROTATION.md): signed and one-time prekeys
- [IDENTITY_PERSISTENCE.md](./IDENTITY_PERSISTENCE.md): identity keys and pinning
- [THREAT_MODEL.md](./THREAT_MODEL.md): what this protects and what it does not

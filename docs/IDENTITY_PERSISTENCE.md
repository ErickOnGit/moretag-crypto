# Identity Keys: Persistence and Pinning (protocol v2)

## Overview

Each device has two identity keys, held by `X3DHPrekeyManagerV2`:

| Key | Algorithm | Field | Used for |
|---|---|---|---|
| DH identity key `IK` | X25519 | `ik.priv32`, `ik.pub32` | X3DH DH1 and DH2 only |
| Signing identity key `IKsig` | Ed25519 (RFC 8032) | `ik_sig.priv32` (the 32-byte seed), `ik_sig.pub32` | Signing the signed prekey and one-time prekey batches only |

`IKsig` signs the signed prekey together with the device id and `IK`, so the signing key vouches for the DH key. Nothing proves possession of the X25519 private key; [THREAT_MODEL.md](./THREAT_MODEL.md) and [SPEC.md](./SPEC.md) describe what that leaves open and how the server's unique-key rule and the associated data limit it.

The library keeps keys in memory and never persists them. The host stores the manager's whole state, encrypted at rest.

## The manager's state

```typescript
import { X3DHPrekeyManagerV2, type X3DHPrekeyManagerStateV2 } from 'moretag-crypto';

const prekeys = X3DHPrekeyManagerV2.create({ recipient_device_id: deviceId }); // canonical UUID
const state: X3DHPrekeyManagerStateV2 = prekeys.exportState();                  // JSON-safe, v: 2
// ... encrypt and store `state` ...
const restored = X3DHPrekeyManagerV2.fromState(state);
```

`X3DHPrekeyManagerStateV2` holds the identity keys, every signed prekey still kept, the one-time prekeys, `current_spk_id` and `next_opk_id`. Ids are integers 1..2^31-1.

`fromState` treats stored state as untrusted input. It checks the version, the device id (a canonical UUID), every key (strict base64, 32 bytes), ids in range with no duplicates, that `current_spk_id` names a held signed prekey, and that `next_opk_id` is above every one-time prekey id. A refusal reads `Corrupt prekey state: <field>`, never the value. A v1 state does not load: protocol v2 sets up every device again (see [VERSION_MIGRATION.md](./VERSION_MIGRATION.md)).

The methods that change it:

| Method | Effect |
|---|---|
| `rotateSignedPrekey(spk_id, now_ms?)` | New current signed prekey; the id must be above every held one. Old ones are kept. |
| `removeSignedPrekey(spk_id)` | Drops a replaced signed prekey; idempotent; refuses the current one. |
| `mintOneTimePrekeys(count, minNextId?, now_ms?)` | New one-time prekeys from `max(next_opk_id, minNextId)`. |
| `removeOneTimePrekey(opk_id)` | Drops one after its first message decrypted; idempotent. |
| `signOneTimePrekeyBatch(opk_ids)` | Signs a batch for publication with `IKsig`. |

Reading a key never consumes it: `getSignedPrekey`, `getOneTimePrekeyPriv32` and `listOneTimePrekeysAbove` return copies. [PREKEY_ROTATION.md](./PREKEY_ROTATION.md) covers when to call each.

Save the state after every change, under one lock per device (the prekey lock), re-reading storage inside the lock. Two tabs or processes that each hold a stale copy must not bring back a deleted one-time prekey or lose a minted one.

## Storing it

Store the exported state encrypted, with the key in the platform's protected store:

- **iOS:** the Keychain, with a class that does not migrate to other devices.
- **Android:** the Keystore; set `android:allowBackup="false"` so app data does not leave the device.
- **Web:** a non-extractable Web Crypto key in IndexedDB, encrypting the state stored beside it.
- **Electron:** `safeStorage`.
- **Node:** a file with mode 0600, encrypted under a key from a secret manager or the OS keychain.

A minimal Node example, using the library's own local seal:

```typescript
import { readFileSync, writeFileSync } from 'node:fs';
import {
  X3DHPrekeyManagerV2,
  sealLocalV2,
  openLocalV2,
} from 'moretag-crypto';

const AAD = new TextEncoder().encode('my-app/prekey-record/v1');

export function savePrekeys(path: string, key32: Uint8Array, prekeys: X3DHPrekeyManagerV2): void {
  const plaintext = new TextEncoder().encode(JSON.stringify(prekeys.exportState()));
  const sealed = sealLocalV2({ key32, aad: AAD, plaintext });
  writeFileSync(path, JSON.stringify(sealed), { mode: 0o600 });
}

export function loadPrekeys(path: string, key32: Uint8Array): X3DHPrekeyManagerV2 {
  const sealed = JSON.parse(readFileSync(path, 'utf-8'));
  const plaintext = openLocalV2({ key32, aad: AAD, ...sealed }); // DecryptFailedError if altered
  return X3DHPrekeyManagerV2.fromState(JSON.parse(new TextDecoder().decode(plaintext)));
}
```

A value that fails to decrypt or parse is an error, never "no keys yet": treating it as absent would mint new identity keys for the same device id, which the server refuses.

## Identity keys never change for a device

A device id has one pair of identity keys for its whole life. The server creates the keys row once, refuses different keys for the same id (`identity_key_changed`) and refuses one identity key under two device ids (`identity_key_in_use`). A new identity is a new device: remove the old device on the server, clear its local crypto state, and register a new device id.

So there is no in-place identity rotation and no grace period for old identity keys.

## No backup of private crypto state

Do not back up or restore identity keys, prekeys or sessions, and do not add such a feature. A restore brings back deleted one-time prekeys, which re-opens replayed first messages, and rolls ratchets back. A device that is lost is replaced by a new device. (An encrypted platform backup of app data is a residual risk the host closes with keychain classes and `allowBackup` false.)

## Pinning peer identities

`IdentityRegistry` pins a peer device's two identity keys on first use and never accepts a change silently.

| Method | Effect |
|---|---|
| `check({ device_id, ik_pub_b64, ik_sig_pub_b64 })` | Returns `'unknown'`, `'match'` or `'mismatch'`; records nothing. |
| `assertOrPin(...)` | Pins on first use; on a mismatch records the block (pending keys, `blocked_mismatch`) and throws `IdentityMismatchError`. |
| `approveRotation(...)` | Accepts a new identity after the user verified it. |
| `remove(device_id)` | Forgets a removed device. |
| `exportState()` / `new IdentityRegistry(state)` | Persistence (`IdentityRegistryStateV1`, unchanged). |

**Pin only after authentication.**

- **Initiator:** `x3dhInitiatorBootstrapV2` verifies the signed-prekey signature, then checks that the bundle names the expected device, then calls `assertOrPin`, then runs DH. A bad signature or another device's bundle pins nothing.
- **Responder:** `x3dhResponderBootstrapV2` takes no registry. The host calls `check` after the first message decrypts on the in-memory state, and `assertOrPin` only in the commit (see [SESSION_LIFECYCLE.md](./SESSION_LIFECYCLE.md)). An unauthenticated sidecar can therefore neither pin nor block a device.

Compare keys as decoded bytes, as the registry does. Key the registry by the server's device id, which is also the id inside the session's associated data.

## Memory

The library wipes, best effort, the secrets it makes during a call (see [SPEC.md](./SPEC.md)). It never wipes arrays it was given. JavaScript gives no guarantee that a wiped secret is gone everywhere: engines and providers may hold copies.

## Checklist

- [ ] The prekey record is stored encrypted, keyed by device id, under a per-device lock.
- [ ] A record that fails to decrypt or parse is an error, not an empty state.
- [ ] No backup or restore of private crypto state; Android `allowBackup` is false.
- [ ] Peers are pinned only after authentication.
- [ ] A new identity means a new device id.

## See Also

- [SPEC.md](./SPEC.md): formats and storage invariants
- [PREKEY_ROTATION.md](./PREKEY_ROTATION.md): signed and one-time prekeys
- [SESSION_LIFECYCLE.md](./SESSION_LIFECYCLE.md): setup and the commit order
- [THREAT_MODEL.md](./THREAT_MODEL.md): the identity compromise table

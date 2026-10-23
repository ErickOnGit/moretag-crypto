# Session Storage Ids (protocol v2)

## Overview

In protocol v2 a device pair has **one bidirectional ratchet state**. The associated data AD inside the state fixes which side is the initiator (A) for the whole session, in both directions, and the header's device ids come from AD by role. There is no separate send session and receive session in the protocol, no `advanceDh` option and no lazy sending step: a state that may send always has a sending chain.

A session storage id is only a lookup key for where the host keeps a state. It is not a secret and it does not protect anything: the binding to the two devices and their keys is AD, which every message authenticates.

## The library's helper

```typescript
import { deriveDirectionScopedSessionIdV1 } from 'moretag-crypto';

const id = deriveDirectionScopedSessionIdV1({
  my_device_id: myDeviceId,
  their_device_id: theirDeviceId,
  direction: 'recv',  // 'send' | 'recv'
  max_len: 52,        // optional, clamped to 16..80 characters of the digest
});
// "dr_" + unpadded base64url of SHA-256(UTF-8 `${my}||${their}||${direction}`), cut to max_len
```

The id is deterministic, differs per direction and per device order, and contains no raw device id. Its format is unchanged in 3.0.0.

## One state per pair, two records until the host's storage change

The protocol needs one state per pair. A host that already stores two records per pair (a receive record and a send record, keyed with `'recv'` and `'send'`) can keep doing so for now, with one rule: **the two records hold the same session.** The receive record is the state; the send record is a clone of it.

- When only one of the two exists, rebuild the other **by cloning** it (`cloneRatchetState`), never by bootstrapping a new session. A new bootstrap would create a second, different session that the peer does not have.
- Both records name the same setup (its ephemeral key and one-time prekey id), so the replay check and the finishing step (see [SESSION_LIFECYCLE.md](./SESSION_LIFECYCLE.md)) see it in either.
- Writes to the pair happen under one pair lock.

A later storage change can fold the two records into one record per pair (holding `current` and, if the placement rule keeps one, `previous`).

## Rules

- **Scope by device, never by user.** A user may have several devices, each with its own keys and sessions. Use the device ids the server assigns (canonical lowercase UUIDs).
- **Do not reuse a dropped state.** After a reset, drop the states and let the next send bootstrap a new session. Reusing the same storage id for the new session is fine: the id only says where the pair's current state lives.
- **Keep metadata beside the state.** Creation time, last message time, message counts and the setup's identifiers belong in host metadata next to the record, not inside `RatchetState`.
- **Do not put ids in logs.** Storage ids derive from device ids; log error `name` and `code` instead.

## Example metadata

```typescript
interface PairRecordMeta {
  storageId: string;          // deriveDirectionScopedSessionIdV1(...)
  myDeviceId: string;
  theirDeviceId: string;
  bootstrapEkB64: string;     // the setup's ephemeral key, to recognise a known setup
  bootstrapOpkId?: number;    // the one-time prekey it used, for the finishing step
  pendingSessionInit?: unknown; // initiator only: sent with every message until a reply decrypts
  createdAt: number;
  lastMessageAt: number;
}
```

## See Also

- [SPEC.md](./SPEC.md): AD, the header and the state format
- [SESSION_LIFECYCLE.md](./SESSION_LIFECYCLE.md): setup, the commit order, placement and reset
- [THREAT_MODEL.md](./THREAT_MODEL.md): what the storage layer must protect

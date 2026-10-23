# Protocol and Package Versions

## Overview

moretag-crypto has two version numbers:

- **The package version** (semantic versioning): what the API promises.
- **The protocol version**: the `v` field in every wire object (`HeaderProtoV2`, `X3DHPrekeyBundleV2`, `X3DHSessionInitV2`) and in the stored state (`RatchetState.version`, `SerializedRatchetStateV2.v`, `X3DHPrekeyManagerStateV2.v`).

### Package version

- Patch (x.y.Z): fixes that change no byte on the wire or at rest.
- Minor (x.Y.0): additions that change no existing byte.
- Major (X.0.0): any change to the public API, a wire format, a byte that enters a KDF, a signature or an AEAD, or a stored format.

### Protocol version

- A wire or stored format, an info string, the AAD or a cryptographic algorithm changes only with a new protocol version, and a new protocol version ships only in a major package release.
- Names whose bytes change get the new version suffix (`…V2`); the old names are removed, not kept beside the new ones.
- Format strings that did not change keep their names, such as the signed-prekey signature domain `moretag/x3dh/spk/v1` and the algorithm strings.

## The rule: one coordinated release with a reset

A protocol change ships as **one coordinated release with a reset**:

- **No dual-version code.** The library speaks one protocol. There is no reader for the old format, no negotiation and no deprecation period.
- **No migration of stored state.** Old sessions and prekey records are not converted. A v1 state does not load: `deserializeRatchetStateV2` refuses `Corrupt session state: v`, `X3DHPrekeyManagerV2.fromState` refuses `Corrupt prekey state: v`, and `FileRatchetStore` refuses files written before the change. Converting a ratchet state across a change of KDF, AAD or initialization would be unsafe even if it were possible.
- **The server resets first.** A one-time fix on the server revokes every old device and deletes the old keys and one-time prekeys, so no old device is served to a new initiator and old devices can no longer send.
- **Every client sets up chat again.** Each client clears its local crypto state, registers a new device with new keys, and starts new sessions.
- **The server change and the client change ship in the same release**, in the order the host's deploy runbook gives (server migration, then functions, then clients).

Messages sent under the old protocol stay unreadable to the new devices; the host decides what to show for them.

This rule fits a product before its first public release, with no customers to carry across. Once there are users, a protocol change needs its own plan, written before the change.

## 3.0.0: protocol v1 to v2

3.0.0 is such a release. Every byte that changed is listed in [SPEC.md](./SPEC.md)'s version table. In short:

- X3DH: the KDF input starts with F (32 bytes of 0xFF), info `moretag/x3dh/v2`; the initiator's Ed25519 key is required.
- Every message's AAD is the 164-byte associated data AD followed by H, a CBOR array of the header with an authenticated group slot.
- The Double Ratchet's initialization follows DR §3.3 (a fresh sending key; the responder starts with no chains); info strings `moretag/v2/rkck` and `moretag/v2/ckmk`.
- Device ids are canonical lowercase UUIDs; prekey ids are integers.
- Bundles, session_init, the header, the serialized state and the prekey record are v2.
- One-time prekeys are served by the server, read without being consumed, and deleted by the host after the first decrypt; batches are signed.
- Removed with no replacement: `allowLegacyFormat`, the archive seal (`sealArchiveV1`, `openArchiveV1`), `ratchetInit`, `advanceDh`, `consumeOneTimePrekey`, `addOneTimePrekeys`, the v1 bootstraps and validators.

Unchanged: the signed-prekey signature message and its golden vector `vectors/spk-sig-msg-v1.json`, `sealAttachmentV1` / `openAttachmentV1`, `deriveDirectionScopedSessionIdV1`, the identity registry's stored format (`IdentityRegistryStateV1`), the `FileRatchetStore` envelope and MAC scheme.

## Stored sessions in FileRatchetStore

### MAC key required, signed and session-bound files (packages 2.2.0 and 2.2.1)

These were storage changes only; the protocol was unchanged. 2.2.0 made the MAC key required; 2.2.1 bound each file to its session, signed the rollback counter, and tightened the load-time checks. 3.0.0 keeps all of this.

- The constructor is `new FileRatchetStore(dir, macKey32)`. The key is required and must be a 32-byte `Uint8Array`; anything else throws a `TypeError`.
- Every session file is signed, and the MAC covers the session ID as well as the contents (envelope `v: 2`), so a file copied over another session's file fails to verify.
- The rollback counter (`<sessionId>.ver`) is signed too, and bound to its session. A counter that is edited, copied from another session, or deleted makes `load()` throw instead of silently skipping the rollback check.
- `load()` throws `Invalid session file: missing mac_b64` for a file without a MAC, `Invalid session file: unsupported envelope version` for any other envelope, and `Corrupt session state: <field>` for a signed file whose contents are malformed (including more than 2,000 skipped keys or bad skipped-key ids).

Load `macKey32` from a persistent secret (OS keychain, secret manager, encrypted config). Do not generate it with `randomBytes(32)` at startup: a key that changes between runs makes every stored session unreadable.

### In 3.0.0

- The payload is the public serialized form (`SerializedPersistedSessionV2`), checked field by field on load.
- `allowLegacyFormat` is gone. 2.2.1 offered it to re-sign 2.1.x and 2.2.0 files once; in 3.0.0 those files, and every file written before 3.0.0, are refused. Under the rule above, discard them and set the sessions up again.
- Only trust files you wrote: a store signs whatever it is given, so re-signing files you cannot vouch for would make tampered contents "valid".

## Checklist for a protocol change

- [ ] Every changed byte is in SPEC's version table, and the vectors cover it.
- [ ] Changed names carry the new suffix; the old ones are removed.
- [ ] Stored formats bump their version, and loaders refuse the old one with a field name, never a value.
- [ ] The server's one-time fix and the client release ship together, in the runbook's order.
- [ ] The release notes say every client sets up chat again.

## See Also

- [SPEC.md](./SPEC.md): protocol v2 and the version table
- [RELEASE.md](./RELEASE.md): tagging and the app's submodule bump
- [Vectors](../vectors/): known-answer vectors for v2
- [SESSION_LIFECYCLE.md](./SESSION_LIFECYCLE.md): setting up sessions after a reset

# Security Policy

## Reporting a vulnerability

Report privately through GitHub's private vulnerability reporting: the
**Security** tab of this repository, then **Report a vulnerability**. Please do
not open a public issue. Include the affected version, how to reproduce it and
what you think the impact is. We aim to acknowledge within 5 business days.

## Supported versions

| Version | Supported |
|---|---|
| 3.x (protocol v2) | yes |
| 2.x and earlier (protocol v1) | no; protocol v1 is retired and gets no fixes |

Fixes land in the latest 3.x release only.

## Scope

- X3DH and the Double Ratchet as `docs/SPEC.md` describes them: X25519,
  Ed25519, HKDF-SHA256, XChaCha20-Poly1305, the 164-byte associated data and the
  CBOR header array.
- The signed-prekey and one-time prekey batch signature messages.
- The prekey manager, the identity registry, the session stores
  (`InMemoryRatchetStore`, `FileRatchetStore`) and the (de)serializers.
- Local seals (`sealLocalV2`) and attachment encryption (`sealAttachmentV1`,
  a fresh random key per attachment, no AAD).
- The pluggable primitives seam and the node-crypto adapter, including the
  registration self-test.

Out of scope: how a host stores keys, transports messages, enforces limits or
places sessions (the host's duties are listed in `docs/SPEC.md` §12), and the
security of the crypto backend a host registers beyond what the self-test checks.

## Dependencies

Four runtime dependencies (`@noble/ciphers`, `@noble/curves`, `@noble/hashes`,
`cbor-x`). Dependabot raises alerts and opens update pull requests; each is
reviewed and none merges automatically. CI runs `npm audit` weekly. The test
vectors are written by a generator that uses only Node's own `crypto`, `fs` and
`path`.

## Known limits

- **Zeroing is best effort.** The library wipes the secret arrays it creates (see
  `docs/SPEC.md` §14), but JavaScript gives no guarantee: a garbage collector, a
  JIT, a crypto provider or a string conversion may keep copies. Treat process
  memory as exposed if the device is compromised.
- **No formal side-channel audit.** The primitives come from @noble or a
  registered backend. In this library's own code, MAC comparisons and the
  all-zero DH check run in constant time.
- **No persistent replay cache.** A replayed first message that used no one-time
  prekey is accepted again after its session is reset or lost (`docs/SPEC.md` §13).
- **Trust on first use.** Identities are pinned on first contact; an active
  attacker who controls the directory on first contact is not detected until
  safety numbers exist.
- **No proof of possession** of the X25519 identity key or of the initiator's
  Ed25519 key (`docs/SPEC.md` §15, §16).
- **Storage.** `FileRatchetStore` detects tampering and simple rollback, not the
  restore of both a session file and its counter. There is no backup of private
  crypto state, and none may be added.

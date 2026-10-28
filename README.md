# moretag-crypto

TypeScript library for end-to-end encrypted messaging: X3DH and the Double
Ratchet as specified by Signal (revision 1, 2016), with documented deviations: a
separate Ed25519 signing key in place of XEdDSA; a signed-prekey signature over a
CBOR array of device id, identity key, signed prekey and id; XChaCha20-Poly1305
with a random nonce; an HKDF chain KDF; Ed25519 keys and device ids appended to
the associated data. `docs/SPEC.md` is the exact description (protocol v2,
package 3.x).

## Features

- **X3DH** with X25519, a separate Ed25519 signing key, HKDF-SHA256 and the F
  prefix; one-time prekeys served by the server, read without being consumed,
  deleted by the host after the first message decrypts.
- **Double Ratchet** initialized as DR §3.3 specifies, one two-way state per
  device pair, skipped-key bounds and replay detection on the current chain.
- **Associated data in every message**: both identity keys, both signing keys
  and both device ids, with the header as a CBOR array and an authenticated group
  slot.
- **XChaCha20-Poly1305** for messages, local seals and attachments.
- **Strict validators** with stable error codes, strict stored-state checks and
  best-effort zeroing.
- **Independent test vectors**, regenerated and compared in every `verify`.

## Installation

The app consumes the library as a git submodule pinned to a release tag; it is
not published to npm.

## Usage

```typescript
import {
  IdentityRegistry,
  X3DHPrekeyManagerV2,
  x3dhInitiatorBootstrapV2,
  x3dhResponderBootstrapV2,
  ratchetEncrypt,
  ratchetDecrypt,
} from "moretag-crypto";

// Device ids are canonical lowercase UUIDs.
const bob = X3DHPrekeyManagerV2.create({ recipient_device_id: bobDeviceId });
const bundle = bob.getPrekeyBundle(); // published; the server adds one one-time prekey per fetch

// Alice: verify the bundle, check the device, pin, then X3DH and the first ratchet state.
const { session_init, ratchet_state: alice } = x3dhInitiatorBootstrapV2({
  sender_device_id: aliceDeviceId,
  recipient_bundle: servedBundle,
  expected_recipient_device_id: bobDeviceId,
  initiator_ik_priv32: aliceKeys.ik.priv32,
  initiator_ik_sig_pub32: aliceKeys.ik_sig.pub32,
  trust: aliceRegistry,
});
const { header, ciphertext_b64 } = ratchetEncrypt({ state: alice, plaintext });
// send header, ciphertext_b64 and session_init (until Bob replies)

// Bob: bootstrap in memory with the sender device from the server row, then decrypt.
const { ratchet_state: bobState, used } = x3dhResponderBootstrapV2({
  session_init,
  prekeys: bob,
  recipient_device_id: bobDeviceId,
  sender_device_id: rowSenderDeviceId,
});
const { plaintext: received } = ratchetDecrypt({ state: bobState, header, ciphertext_b64 });
// then check and pin Alice's keys, save the state, and only then
// bob.removeOneTimePrekey(used.opk_id) (docs/SPEC.md §12)
```

## Public API

### Wire formats and validators
- `X3DHPrekeyBundleV2`, `X3DHSessionInitV2`, `HeaderProtoV2`, `DoubleRatchetHeader`, `GroupSlotV2`, `MessagePayloadV1`
- `assertX3DHPrekeyBundleV2`, `assertX3DHSessionInitV2`, `assertHeaderProtoV2` and the `decode…V2` forms that return decoded bytes
- `isCanonicalDeviceId`, `assertCanonicalDeviceId`, `deviceIdToBytes`, `deviceIdFromBytes`

### Sessions
- **Bootstraps**: `x3dhInitiatorBootstrapV2`, `x3dhResponderBootstrapV2`
- **X3DH**: `x3dhInitiatorV2`, `x3dhResponderV2`, `verifyPrekeyBundleV2`, `buildSpkSigMessage`, `buildOpkBatchSigMessage`
- **Associated data**: `buildAssociatedDataV2`, `parseAssociatedDataV2`, `buildDeliveryAadV2`, `encodeHeaderV2`
- **Ratchet**: `ratchetInitInitiatorV2`, `ratchetInitResponderV2`, `ratchetEncrypt`, `ratchetDecrypt`, `cloneRatchetState`
- **Stores**: `InMemoryRatchetStore`, `ratchetEncryptWithStore`, `ratchetDecryptWithStore`, `createPersistedSession`; `FileRatchetStore` from `moretag-crypto/node`
- **Serialization**: `serializeRatchetStateV2`, `deserializeRatchetStateV2`, `serializePersistedSessionV2`, `deserializePersistedSessionV2`
- **Keys and trust**: `X3DHPrekeyManagerV2`, `IdentityRegistry` (`check`, `assertOrPin`, `approveRotation`)
- **Session ids**: `deriveDirectionScopedSessionIdV1`

### Seals and primitives
- `sealDeliveryV2`, `openDeliveryV2`, `sealLocalV2`, `openLocalV2`, `buildSelfSealAadV2`, `sealAttachmentV1`, `openAttachmentV1`
- `aeadEncryptXChaCha20Poly1305`, `aeadDecryptXChaCha20Poly1305`, `randomNonce24`, `randomKey32`
- `generateX25519Keypair`, `x25519PublicFromPrivate`, `x25519SharedSecret`, `generateEd25519Keypair`, `ed25519Sign`, `ed25519Verify`, `hkdfSha256`, `kdfRootAndChainKey`, `kdfChainKey`
- `bytesToBase64`, `base64ToBytes`

### Errors
Every typed error has a stable `code` (table in `docs/SPEC.md` §11):
`ReplayDetectedError`, `DecryptFailedError`, `UnknownPrekeyError`,
`DeviceMismatchError`, `SelfSessionError`, `NoSendingChainError`,
`SkipLimitError`, `InvalidDeviceIdError`, `InvalidWireError`, `BadSignatureError`,
`LowOrderKeyError`, `IdentityMismatchError`, `SessionNotFoundError`,
`RatchetStoreConflictError`, `StoreIoError`. Messages never name an id or a stored value; log
`name` and `code`.

### Pluggable Primitives (optional)
- `registerCryptoPrimitives`, `resetCryptoPrimitives`, `getCryptoPrimitivesProviderName`

The package is pure JS (@noble) by default and stays free of native
dependencies. Hosts running on VMs without a JIT (e.g. React Native/Hermes,
where pure-JS crypto is 10-50x slower) can inject faster low-level primitives:

```ts
import { registerCryptoPrimitives } from "moretag-crypto";
import { createNodeCryptoPrimitives } from "moretag-crypto/providers/node-crypto";
import QuickCrypto from "react-native-quick-crypto"; // or node:crypto

registerCryptoPrimitives(
  createNodeCryptoPrimitives(QuickCrypto, { name: "quick-crypto" })
);
```

Providers may override any subset of primitives (x25519, ed25519,
XChaCha20-Poly1305, HKDF-SHA256, randomBytes); the rest keep the @noble
defaults. A provider must supply a CSPRNG `randomBytes`. Registration
self-tests every supplied primitive and rejects the provider on any divergence:
each must reproduce published test vectors (RFC 7748 §6.1, RFC 8032 §7.1 test 1,
RFC 5869 A.1 and A.3, draft-irtf-cfrg-xchacha-03 A.3.1) and match the built-in
@noble implementation on fixed inputs at the sizes the protocol uses. This
catches a backend that is wrong on those inputs; it cannot prove a backend
right on every input. See `src/crypto/primitives.ts` for the full contract.

## Validation

Every v2 validator decodes what it checks: version and algorithm, canonical
device ids, strict base64 with exact decoded lengths, ids in 1..2^31-1 and the
one-time prekey invariants. A refusal is an `InvalidWireError` or
`InvalidDeviceIdError` with a stable code, naming the field and never its value.
Signatures, DH and the AEAD run only on validated input.

## Development

```bash
# Install dependencies
npm ci

# Everything CI runs: typecheck, test typecheck, vectors:check, tests, build
npm run verify

# Regenerate the vector files (then review the diff)
npm run vectors
```

## Production Guides

For production deployments, refer to these detailed guides:

### Security & Architecture
- [Session ID Guidelines](docs/SESSION_ID_GUIDELINES.md) - How to generate secure session identifiers
- [Identity Persistence](docs/IDENTITY_PERSISTENCE.md) - Securely storing device identity keys
- [Session Lifecycle](docs/SESSION_LIFECYCLE.md) - Session expiry and rekey policies

### Operational Procedures
- [Prekey Rotation](docs/PREKEY_ROTATION.md) - Signed prekey rotation, one-time prekey publication and pruning
- [Version Migration](docs/VERSION_MIGRATION.md) - Protocol changes ship as one coordinated release with a reset
- [Release](docs/RELEASE.md) - Tagging a release and moving the app's submodule
- [Integration Test](src/integration.test.ts) - Complete end-to-end example

### Specifications
- [Protocol v2 Spec](docs/SPEC.md) - Formats, draw order, errors, host duties, residuals
- [Threat Model](docs/THREAT_MODEL.md) - Assets, boundaries, key compromise, gaps

## Operational Guidance

- **Input validation**: every entry point refuses malformed input with a stable code before any key is used.
- **Size limits**: plaintext up to about 1 MB, ciphertext slightly above; skipped-key cache bounded at 2,000 (oldest evicted) with a single gap of at most 1,000.
- **Storage**: `FileRatchetStore` (Node only) requires a 32-byte MAC key, signs every session file and a rollback counter, and refuses files that are unsigned, tampered with, malformed or older than their counter. It does not stop the restore of both files; use storage with rollback resistance for that threat. Keep the MAC key secret and stable.
- **Identity**: two-key pinning on first use. The initiator pins after verifying the bundle; the responder checks with `IdentityRegistry.check` and pins only after the first message decrypts.
- **No backup of private crypto state**: restoring one would bring back deleted one-time prekeys and roll ratchets back.
- **Vectors**: five files in `vectors/` (`primitives.json`, `x3dh-v2.json`, `ratchet-v2.json`, `aead-edges.json`, `spk-sig-msg-v1-independent.json`) are independent known-answer vectors from `scripts/gen-vectors-v2.mjs`, which uses only Node's `crypto`, `fs` and `path`; `npm run vectors:check` must keep them byte-identical. `opk-batch-sig-msg-v1.json` is written by the library and checked against the generator's CBOR encoder and node:crypto; `spk-sig-msg-v1.json` is the unchanged v1 file. See `docs/SPEC.md` §18.

## Security

This library implements cryptographic protocols. Please:
- Review the code before using in production
- Report security issues privately (see SECURITY.md)
- Keep dependencies updated

## Architecture

- `src/wire/` - Wire format types and structural validators (no crypto)
- `src/crypto/` - Cryptographic operations and validations
- `src/x3dh/` - Prekey lifecycle and X3DH session/bootstrap helpers
- `src/ratchet/` - Double Ratchet state machine and persistence adapters
- `src/identity/` - Identity pinning and trust management utilities
- `src/encoding/` - Base64 and shortest-form CBOR
- `scripts/` and `vectors/` - The independent vector generator, its five files, and the library's two signature-message golden files (`docs/SPEC.md` §18)

## License

See [LICENSE](LICENSE) file for details.

## Contributing

This is a security-sensitive project. All contributions must:
1. Pass existing tests (`npm test`)
2. Include tests for new functionality
3. Follow TypeScript strict mode
4. Not break the public API without major version bump

Pull requests welcome!

# moretag-crypto

TypeScript cryptographic library for end-to-end encrypted messaging with Signal-style
session setup (X3DH) and message encryption (Double Ratchet).

## Features

- **X3DH v1** - Extended Triple Diffie-Hellman key agreement using X25519 + Ed25519 + HKDF-SHA256
- **XChaCha20-Poly1305** - Authenticated encryption with associated data (AEAD)
- **Double Ratchet v1** - Stateful per-session send/receive ratchet with skipped-key handling
- **Wire Format Types** - Structured validators for message formats
- **Base64 Encoding** - Utilities for encoding/decoding cryptographic material

## Installation

```bash
npm install moretag-crypto
```

## Usage

```typescript
import {
  x3dhInitiatorV1,
  x3dhResponderV1,
  type X3DHPrekeyBundleV1,
  type X3DHSessionInitV1
} from 'moretag-crypto';

// Example: X3DH key agreement
const { session_init, rk32 } = x3dhInitiatorV1({
  sender_device_id: 'alice-device-1',
  recipient_bundle: recipientBundle,
  initiator_ik_priv32: aliceIdentityKey
});
```

## Public API

### Wire Format Types
- `X3DHPrekeyBundleV1`, `X3DHSessionInitV1` - X3DH message structures
- `HeaderProtoV1`, `ArchiveHeaderV1`, `DoubleRatchetHeader` - Message header types
- `MessagePayloadV1` - Payload structure
- `UUID`, `Base64String` - Primitive type aliases

### Wire Format Validators
- `assertX3DHPrekeyBundleV1`, `assertX3DHSessionInitV1` - X3DH validators
- `assertHeaderProtoV1`, `assertArchiveHeaderV1` - Header validators

### Cryptographic Functions
- **X3DH**: `x3dhInitiatorV1`, `x3dhResponderV1`
- **X3DH Lifecycle**: `X3DHPrekeyManagerV1`, `x3dhInitiatorWithTrustV1`, `x3dhResponderWithPrekeysV1`, `x3dhInitiatorBootstrapV1`, `x3dhResponderBootstrapV1`
- **AEAD**: `aeadEncryptXChaCha20Poly1305`, `aeadDecryptXChaCha20Poly1305`, `randomNonce24`, `assertKeyNonceLengths`
- **Key Agreement**: `generateX25519Keypair`, `x25519PublicFromPrivate`, `x25519SharedSecret`
- **Signing**: `generateEd25519Keypair`, `ed25519Sign`, `ed25519Verify`
- **KDF**: `hkdfSha256`, `kdfRootAndChainKey`, `kdfChainKey`
- **High-level**: `sealDeliveryV1`, `openDeliveryV1`, `sealArchiveV1`, `openArchiveV1`
- **Utilities**: `encodeAADFromHeaderV1`, `decodeNonceFromHeaderV1`, `decodeDhPubFromHeaderV1`

### Encoding Utilities
- `bytesToBase64`, `base64ToBytes`

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
defaults. A provider must supply a CSPRNG `randomBytes`, and registration runs
known-answer self-tests of every supplied primitive against the reference
implementation, rejecting the provider on any divergence — a subtly
incompatible backend can never silently corrupt sessions. See
`src/crypto/primitives.ts` for the full contract.

## Wire vs Crypto Validation

This library separates validation concerns into two layers:

**Wire Layer** (`src/wire/`)
- Validates object shape and field types
- Checks that required fields are present and have correct primitive types
- Does NOT validate base64 encoding or decoded byte lengths
- Does NOT perform cryptographic operations

**Crypto Layer** (`src/crypto/`)
- Decodes base64 strings with error handling
- Enforces exact byte lengths (X25519 pub: 32B, Ed25519 pub: 32B, Ed25519 sig: 64B)
- Verifies cryptographic signatures (e.g., SPK signature in X3DH)
- Performs key agreement (DH) and key derivation (HKDF)

**Usage Pattern:**
1. First validate wire format structure: `assertX3DHPrekeyBundleV1(bundle)`
2. Then pass to crypto functions which enforce crypto invariants: `x3dhInitiatorV1(...)`

This separation allows wire format validation without crypto dependencies and ensures crypto operations always receive structurally valid input.

## Development

```bash
# Install dependencies
npm install

# Run tests
npm test

# Build
npm run build
```

## Production Guides

For production deployments, refer to these detailed guides:

### Security & Architecture
- [Session ID Guidelines](docs/SESSION_ID_GUIDELINES.md) - How to generate secure session identifiers
- [Identity Persistence](docs/IDENTITY_PERSISTENCE.md) - Securely storing device identity keys
- [Session Lifecycle](docs/SESSION_LIFECYCLE.md) - Session expiry and rekey policies

### Operational Procedures
- [Prekey Rotation](docs/PREKEY_ROTATION.md) - SPK/OPK rotation schedules and automation
- [Version Migration](docs/VERSION_MIGRATION.md) - Handling protocol upgrades
- [Integration Test](src/integration.test.ts) - Complete end-to-end example

### Specifications
- [Wire Format Spec](docs/SPEC.md) - Stable v1 protocol definition
- [Threat Model](docs/THREAT_MODEL.md) - Security assumptions and mitigations

## Operational Guidance (v1)

- **Input validation**: All crypto entrypoints enforce strict base64, version/alg, and length limits by default.
- **Size limits**: Plaintext limited to ~1MB, ciphertext slightly above; ratchet skipped-key cache bounded (2k) with derivation window (1k).
- **Storage**: Use the provided session store interfaces. `FileRatchetStore` writes atomically and tracks a monotonic version counter to detect simple rollbacks. For production, back with durable storage and consider hardware-backed key protection.
- **Storage integrity**: `FileRatchetStore` can optionally MAC persisted sessions (`macKey32`) to detect on-disk tampering. This does not prevent full rollback if an attacker can restore *both* the session and counter files; use an OS/DB mechanism with rollback resistance for that threat model.
- **Identity**: TOFU-style identity pinning with optional rotation (`IdentityRegistry`). Reject mismatches unless explicitly rotating.
- **Interop**: Deterministic vectors live under `vectors/` for AAD and SPK signature message framing.
- **Spec**: Stable v1 wire/state spec is in `docs/SPEC.md`. v1.x commits to backward compatibility with these formats and invariants.

## Security

This library implements cryptographic protocols. Please:
- Review the code before using in production
- Report security issues privately (see SECURITY.md if available)
- Keep dependencies updated

## Architecture

- `src/wire/` - Wire format types and structural validators (no crypto)
- `src/crypto/` - Cryptographic operations and validations
- `src/x3dh/` - Prekey lifecycle and X3DH session/bootstrap helpers
- `src/ratchet/` - Double Ratchet state machine and persistence adapters
- `src/identity/` - Identity pinning and trust management utilities
- `src/encoding/` - Base64 and other encoding utilities

## License

See [LICENSE](LICENSE) file for details.

## Contributing

This is a security-sensitive project. All contributions must:
1. Pass existing tests (`npm test`)
2. Include tests for new functionality
3. Follow TypeScript strict mode
4. Not break the public API without major version bump

Pull requests welcome!

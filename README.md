# moretag-crypto

TypeScript cryptographic library for end-to-end encrypted messaging with X3DH key agreement.

## Features

- **X3DH v1** - Extended Triple Diffie-Hellman key agreement using X25519 + Ed25519 + HKDF-SHA256
- **XChaCha20-Poly1305** - Authenticated encryption with associated data (AEAD)
- **Double Ratchet Primitives** - KDF functions and header encoding utilities
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

## Development

```bash
# Install dependencies
npm install

# Run tests
npm test

# Build
npm run build
```

## Security

This library implements cryptographic protocols. Please:
- Review the code before using in production
- Report security issues privately (see SECURITY.md if available)
- Keep dependencies updated

## Architecture

- `src/wire/` - Wire format types and structural validators (no crypto)
- `src/crypto/` - Cryptographic operations and validations
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

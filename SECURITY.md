# Security Policy

## Reporting
- Please report vulnerabilities privately (not via public issues). Send details to `security@moretag.example` (update to your real channel).
- Include: affected version, PoC/reproduction steps, and any impact assessment. We will acknowledge within 5 business days.
 - If you do not control `security@moretag.example`, replace it before publishing.

## Supported Versions
- Current: `1.x`
- We do not backport fixes to unsupported versions; upgrade to the latest patch.

## Cryptographic Scope (v1)
- X3DH: X25519 + HKDF-SHA256 + Ed25519 with CBOR-framed SPK signature message.
- AEAD: XChaCha20-Poly1305 with canonical CBOR AAD.
- Double Ratchet MVP: symmetric-only storage with skipped-key bounds; no attachments.

## Known Limitations (must be addressed before production)
- No formal side-channel audit; @noble primitives are used, but call-site constant-time behavior not formally proven.
- No on-disk secure deletion; file-based stores should assume disk persistence.
- No server-side rate limits or DoS defenses beyond local size/windows.
- Trust-on-first-use identity; no multi-device consensus or cross-signing yet.
- Dependency updates must be monitored; no automatic advisories are wired.

## Operational Guidance
- Run latest patch version.
- Enforce strict base64/length validation (enabled by default).
- Rotate prekeys and ratchet states regularly; clear skipped-key caches on device removal.
- Monitor logs without persisting secrets; avoid logging headers/ciphertexts in production.

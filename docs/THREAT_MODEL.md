# Threat Model (v1 snapshot)

## Assets
- Long-term identity keys (X25519, Ed25519).
- Signed prekeys and one-time prekeys.
- Ratchet state (root key, chain keys, DH keys, skipped message keys).
- Encrypted message payloads and headers (AAD).

## Trust Boundaries
- Client boundary: input validation for wire data (base64, lengths, versions).
- Storage boundary: session store persistence (disk/DB) must prevent rollback/replay.
- Network boundary: untrusted transport; authenticity derives from keys + AAD.

## Attacker Goals
- Replay or reorder messages to confuse state.
- Swap identity keys (IK) to hijack sessions.
- Downgrade algorithms or bypass validation.
- Exhaust resources via large payloads or large gaps.
- Extract keys from storage or logs.

## Current Mitigations
- Strict base64/length/version checks; CBOR-framed SPK signature message.
- AAD canonicalization with deterministic CBOR.
- Ratchet skipped-key/window limits; constant-time DH pub comparison.
- Identity pinning/rotation helper (TOFU) with explicit mismatch errors.
- Session store interface with atomic save path and replay prevention hooks.

## Gaps / Next Work
- Formal side-channel review of call sites (constant-time usage).
- Durable storage with rollback protection (e.g., monotonic counters, signatures).
- Rate limiting / DoS handling beyond local limits.
- Multi-device identity trust (cross-signing) and prekey rotation policies.
- Expanded fuzz/stress + long-run soak tests for ratchet ordering/loss/duplication.

## Residual Risks
- TOFU can be subverted on first contact if an active attacker controls network.
- If storage is compromised, lack of hardware-backed keys/secure deletion leaves state exposed.
- Dependency vulnerabilities could impact primitives; needs continuous monitoring.

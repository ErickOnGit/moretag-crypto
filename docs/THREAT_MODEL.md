# Threat model (protocol v2, package 3.x)

## Assets

- Identity keys: IK (X25519, DH only) and IKsig (Ed25519, signatures only).
- Signed prekeys (current and retained) and one-time prekeys.
- Ratchet state: root key, chain keys, the current DH key pair, skipped message
  keys, and the session's associated data.
- Message plaintexts, and the local-seal key a host keeps for its own copies.

## Trust boundaries

- **Wire.** Every header, bundle and `session_init` is untrusted; validators check
  shape, canonical device ids, strict base64 and exact lengths before any key is
  used.
- **Server.** Untrusted for confidentiality. It serves bundles and one-time
  prekeys, can withhold them (forcing the fallback, X3DH §4.7), replay old
  messages, and is the source of the row's sender device the host passes in.
- **Storage.** Stored state is untrusted on load and checked field by field;
  `FileRatchetStore` adds a MAC bound to the session id and a signed rollback
  counter.
- **Crypto backend.** A registered provider must pass the registration
  self-test; it is trusted after that.

## Attacker goals and what stops them

| Goal | Mitigation | Residual |
|---|---|---|
| Replay or reorder messages | Skipped-key bounds; `replay_detected` on the current chain; an earlier-chain replay fails the AEAD; decrypt changes state only on success | A replayed fallback setup after a reset (no persistent replay cache) |
| Present a valid setup as another device or identity (unknown-key share, X3DH §4.8) | AD carries both X25519 keys, both Ed25519 keys and both device ids in every AEAD; header ids checked against AD; the responder takes the sender device from the row | A hostile server rewriting rows |
| Swap identity keys | Two-key pinning; verify the bundle signature and the expected device before pinning; the responder pins only after a message authenticates | First contact under an attacker-controlled directory (until safety numbers) |
| Burn a one-time prekey or break a session with a forged first message | Bootstrap in memory, trial-decrypt, then commit; nothing is consumed before the first message decrypts | Draining the pool up to the server's limits, which leads to the fallback |
| Downgrade or bypass validation | Version 2 only; no v1 path; strict validators with stable codes | — |
| Exhaust resources | Size limits; a gap over 1,000 refused; at most 2,000 skipped keys | — |
| Read keys from memory or logs | Best-effort zeroing; messages carry no identifiers or stored values | Copies an engine or provider keeps |

## Key compromise

| Stolen | What the attacker gains | Residual |
|---|---|---|
| IK alone | Can initiate as the victim to anyone and present the victim's public IKsig (nothing proves possession of it). Cannot act as responder. No past sessions | Impersonation to others until the device is removed |
| IKsig alone | No confidentiality, but full **control-plane authority**: it signs signed prekeys, one-time prekey batches and, later, device proofs | A concentration of risk; device proofs must cover it |
| A signed prekey | **Key-compromise impersonation** against the victim on setups naming that id, for as long as the key is held: the current one, and a replaced one for 30 days after the server confirms its successor (30 to 37 days in all with weekly rotation). With IK, the first messages sent on it without a one-time prekey | The retention window |
| A one-time prekey | Nothing once it is deleted after its first message | — |
| The whole device | Everything | Both identity keys share one storage class |

The full table, with the comparison to a single XEdDSA key, is in
`docs/SPEC.md` §15.

## Gaps

- No persistent replay cache; the fallback's replay residual stays until one exists.
- No proof of possession of the X25519 identity key or the initiator's Ed25519 key.
- No conversation binding (a hostile server moving a ciphertext between two
  conversations of the same device pair).
- No header encryption; no post-quantum key agreement.
- No formal side-channel review of call sites.
- A same-device encrypted iOS backup restore brings deleted keys back until the
  app's storage sets a keychain class that excludes backups.

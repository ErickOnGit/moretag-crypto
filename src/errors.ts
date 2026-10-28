/**
 * Typed errors thrown by the ratchet/session/identity layers.
 *
 * Consumers (e.g. the app's cryptoService / im message flow) branch on these via
 * `instanceof` or on their stable `code`, so their names, codes and shapes are part
 * of the public contract.
 *
 * Messages never contain a caller-supplied identifier (device id, session id,
 * prekey id) or a stored value: hosts log them, and logs must stay free of
 * identifiers. Hosts should log `name` and `code`, not the message.
 */

/**
 * Thrown when a received message key has already been consumed — i.e. a replay
 * of an earlier message. Distinct from a generic decrypt failure so callers can
 * treat replays as benign (drop) rather than as session corruption.
 *
 * Limits: `ratchetDecrypt` recognises a replay only on the current receiving
 * chain (same DH key, a message number below the next expected one, and no
 * skipped key left for it). A replay from an earlier receiving chain fails
 * authentication instead ({@link DecryptFailedError}). Nothing here survives the
 * loss or rollback of the stored session state: a state restored from before the
 * message was read accepts it again. This is not a persistent replay cache.
 */
export class ReplayDetectedError extends Error {
  readonly code = "replay_detected" as const;

  constructor(message: string = "Replay detected: message key already consumed") {
    super(message);
    this.name = "ReplayDetectedError";
  }
}

/**
 * Thrown when a ratchet session is requested but not present in the store.
 */
export class SessionNotFoundError extends Error {
  readonly code = "session_not_found" as const;

  constructor(message: string = "Session not found") {
    super(message);
    this.name = "SessionNotFoundError";
  }
}

/**
 * Thrown when an optimistic, version-checked session update loses a race with a
 * concurrent writer. Callers typically reload and retry.
 */
export class RatchetStoreConflictError extends Error {
  readonly code = "store_conflict" as const;

  constructor(message: string = "Session update conflict") {
    super(message);
    this.name = "RatchetStoreConflictError";
  }
}

/**
 * Thrown when a peer's observed identity keys differ from the pinned (trusted)
 * ones — i.e. the safety number changed. Carries both key sets so the UI can
 * surface a verification prompt; the message itself names neither.
 */
export class IdentityMismatchError extends Error {
  readonly code = "identity_mismatch" as const;
  readonly deviceId: string;
  readonly pinnedIkPubB64: string;
  readonly observedIkPubB64: string;
  readonly pinnedIkSigPubB64: string;
  readonly observedIkSigPubB64: string;

  constructor(args: {
    deviceId: string;
    pinnedIkPubB64: string;
    observedIkPubB64: string;
    pinnedIkSigPubB64: string;
    observedIkSigPubB64: string;
  }) {
    super("Safety number changed: pinned identity mismatch");
    this.name = "IdentityMismatchError";
    this.deviceId = args.deviceId;
    this.pinnedIkPubB64 = args.pinnedIkPubB64;
    this.observedIkPubB64 = args.observedIkPubB64;
    this.pinnedIkSigPubB64 = args.pinnedIkSigPubB64;
    this.observedIkSigPubB64 = args.observedIkSigPubB64;
  }
}

/**
 * Thrown when AEAD authentication fails: wrong key, altered ciphertext, altered
 * associated data or nonce. Replaces whatever the crypto provider threw, so every
 * backend fails the same way and no provider text reaches the host.
 */
export class DecryptFailedError extends Error {
  readonly code = "decrypt_failed" as const;

  constructor() {
    super("Decryption failed");
    this.name = "DecryptFailedError";
  }
}

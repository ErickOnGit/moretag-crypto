/**
 * Typed errors thrown by the ratchet/session/identity layers.
 *
 * Consumers (e.g. the app's cryptoService / im message flow) branch on these via
 * `instanceof`, so their names and shapes are part of the public contract.
 */

/**
 * Thrown when a received message key has already been consumed — i.e. a replay
 * of an earlier message. Distinct from a generic decrypt failure so callers can
 * treat replays as benign (drop) rather than as session corruption.
 */
export class ReplayDetectedError extends Error {
  constructor(message: string = "Replay detected: message key already consumed") {
    super(message);
    this.name = "ReplayDetectedError";
  }
}

/**
 * Thrown when a ratchet session is requested but not present in the store.
 */
export class SessionNotFoundError extends Error {
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
  constructor(message: string = "Session update conflict") {
    super(message);
    this.name = "RatchetStoreConflictError";
  }
}

/**
 * Thrown when a peer's observed identity keys differ from the pinned (trusted)
 * ones — i.e. the safety number changed. Carries both key sets so the UI can
 * surface a verification prompt.
 */
export class IdentityMismatchError extends Error {
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

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

/**
 * Thrown when a setup names a prekey this device does not hold: `unknown_spk` for
 * a signed prekey, `unknown_opk` for a one-time prekey (never published, already
 * used and deleted, or pruned). Nothing was consumed.
 */
export class UnknownPrekeyError extends Error {
  readonly code: "unknown_spk" | "unknown_opk";

  constructor(code: "unknown_spk" | "unknown_opk") {
    super(code === "unknown_spk" ? "Unknown signed prekey" : "Unknown one-time prekey");
    this.name = "UnknownPrekeyError";
    this.code = code;
  }
}

/**
 * Thrown when a device id disagrees with the one the session or the host expects:
 * a bundle for another device than the one asked for, a session_init whose sender
 * differs from the server row's sender or whose recipient is not this device, or a
 * header whose ids differ from the session's associated data. Raised before any
 * key derivation or AEAD.
 */
export class DeviceMismatchError extends Error {
  readonly code = "device_mismatch" as const;

  constructor() {
    super("Device id does not match the session");
    this.name = "DeviceMismatchError";
  }
}

/** Thrown when both ends of a session would be the same device. */
export class SelfSessionError extends Error {
  readonly code = "self_session" as const;

  constructor() {
    super("A session needs two different devices");
    this.name = "SelfSessionError";
  }
}

/**
 * Thrown when a state that has no sending chain is asked to encrypt: a responder
 * state before its first received message.
 */
export class NoSendingChainError extends Error {
  readonly code = "no_sending_chain" as const;

  constructor() {
    super("Session has no sending chain yet");
    this.name = "NoSendingChainError";
  }
}

/**
 * Thrown when a received header's message number (or, before a DH step, its `pn`)
 * lies more than MAX_SKIP (1,000, DR §3.5) past the receiving chain's next number.
 * Raised before any AEAD, so the header is unauthenticated: a peer or the server
 * can cause it. Nothing is stored.
 */
export class SkipLimitError extends Error {
  readonly code = "skip_limit_exceeded" as const;

  constructor() {
    super("Message gap exceeds the skip limit");
    this.name = "SkipLimitError";
  }
}

/** Thrown when a device id is not a canonical lowercase UUID string. */
export class InvalidDeviceIdError extends TypeError {
  readonly code = "invalid_device_id" as const;

  constructor() {
    super("Device id is not a canonical lowercase UUID");
    this.name = "InvalidDeviceIdError";
  }
}

/** The wire object an {@link InvalidWireError} refers to. */
export type InvalidWireCode =
  | "invalid_header"
  | "invalid_grp"
  | "invalid_session_init"
  | "invalid_bundle";

/**
 * Thrown when a wire object (header, its group slot, session_init, prekey bundle)
 * has the wrong shape: a missing or extra-typed field, bad base64, a wrong decoded
 * length, an id out of range. A message's `ciphertext_b64` that is not strict
 * base64 or is over MAX_CIPHERTEXT_BYTES is `invalid_header` with that field. The
 * message names the field, never its value.
 */
export class InvalidWireError extends TypeError {
  readonly code: InvalidWireCode;

  constructor(code: InvalidWireCode, field: string) {
    super(`Invalid ${code.slice("invalid_".length)}: ${field}`);
    this.name = "InvalidWireError";
    this.code = code;
  }
}

/** Thrown when a prekey bundle's signed-prekey signature does not verify. */
export class BadSignatureError extends Error {
  readonly code = "bad_signature" as const;

  constructor() {
    super("Signature verification failed");
    this.name = "BadSignatureError";
  }
}

/**
 * Thrown when an X25519 agreement gives the all-zero output, which happens exactly
 * when the peer's public key is a low-order point (RFC 7748 §6.1). The provider's
 * own refusal is replaced by this error, so every backend fails the same way.
 */
export class LowOrderKeyError extends Error {
  readonly code = "low_order_key" as const;

  constructor() {
    super("Low-order public key: all-zero shared secret");
    this.name = "LowOrderKeyError";
  }
}

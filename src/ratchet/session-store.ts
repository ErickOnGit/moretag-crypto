import { ratchetEncrypt, ratchetDecrypt, type RatchetState } from "./ratchet.js";
import { SessionNotFoundError } from "../errors.js";

export interface PersistedSession {
  version: number;
  state: RatchetState;
}

/**
 * Storage for ratchet sessions, keyed by session id.
 *
 * `transact`, when present, is the store's atomic read-modify-write, and the
 * with-store helpers use it instead of `load` then `save`. Its contract:
 * - It is atomic per session id: no other write to that id lands between the
 *   read that produces `current` and the write of `fn`'s result.
 * - A missing id throws {@link SessionNotFoundError} without calling `fn`.
 * - If `fn` throws, nothing is persisted and the same error is rethrown.
 * - Otherwise the store persists exactly the record `fn` returns, and returns it.
 */
export interface RatchetSessionStore {
  load(sessionId: string): Promise<PersistedSession | undefined> | PersistedSession | undefined;
  save(sessionId: string, record: PersistedSession): Promise<void> | void;
  transact?(
    sessionId: string,
    fn: (current: PersistedSession) => PersistedSession
  ): Promise<PersistedSession> | PersistedSession;
}

/** Ratchet arguments for the with-store helpers: the store's record is the only state. */
type EncryptWithStoreArgs = Omit<Parameters<typeof ratchetEncrypt>[0], "state">;
type DecryptWithStoreArgs = Omit<Parameters<typeof ratchetDecrypt>[0], "state">;

export function cloneRatchetState(state: RatchetState): RatchetState {
  return {
    version: state.version,
    rk32: new Uint8Array(state.rk32),
    ck_s32: state.ck_s32 ? new Uint8Array(state.ck_s32) : undefined,
    ck_r32: state.ck_r32 ? new Uint8Array(state.ck_r32) : undefined,
    ns: state.ns,
    nr: state.nr,
    pn: state.pn,
    dh_self: {
      priv32: new Uint8Array(state.dh_self.priv32),
      pub32: new Uint8Array(state.dh_self.pub32),
    },
    dh_remote_pub32: new Uint8Array(state.dh_remote_pub32),
    skipped: new Map(
      Array.from(state.skipped.entries()).map(([k, v]) => [k, new Uint8Array(v)])
    ),
  };
}

export function createPersistedSession(state: RatchetState): PersistedSession {
  return { version: 0, state: cloneRatchetState(state) };
}

export class InMemoryRatchetStore implements RatchetSessionStore {
  private records = new Map<string, PersistedSession>();

  load(sessionId: string): PersistedSession | undefined {
    const rec = this.records.get(sessionId);
    return rec ? { version: rec.version, state: cloneRatchetState(rec.state) } : undefined;
  }

  save(sessionId: string, record: PersistedSession): void {
    this.records.set(sessionId, {
      version: record.version,
      state: cloneRatchetState(record.state),
    });
  }

  transact(sessionId: string, fn: (current: PersistedSession) => PersistedSession): PersistedSession {
    const current = this.load(sessionId);
    if (!current) throw new SessionNotFoundError();
    const next = fn(current);
    this.save(sessionId, next);
    return next;
  }
}

export async function ratchetEncryptWithStore(
  store: RatchetSessionStore,
  sessionId: string,
  args: EncryptWithStoreArgs
): Promise<{ header: ReturnType<typeof ratchetEncrypt>["header"]; ciphertext_b64: string }> {
  if (store.transact) {
    let out:
      | { header: ReturnType<typeof ratchetEncrypt>["header"]; ciphertext_b64: string }
      | undefined;
    await store.transact(sessionId, (current) => {
      const state = cloneRatchetState(current.state);
      const { header, ciphertext_b64 } = ratchetEncrypt({ ...args, state });
      out = { header, ciphertext_b64 };
      return { version: current.version + 1, state };
    });
    if (!out) throw new Error("Unexpected: missing encrypt output");
    return out;
  }

  const record = await store.load(sessionId);
  if (!record) throw new SessionNotFoundError();
  const state = cloneRatchetState(record.state);
  const { header, ciphertext_b64 } = ratchetEncrypt({ ...args, state });
  await store.save(sessionId, { version: record.version + 1, state });
  return { header, ciphertext_b64 };
}

export async function ratchetDecryptWithStore(
  store: RatchetSessionStore,
  sessionId: string,
  args: DecryptWithStoreArgs
): Promise<{ plaintext: Uint8Array }> {
  if (store.transact) {
    let out: { plaintext: Uint8Array } | undefined;
    await store.transact(sessionId, (current) => {
      const state = cloneRatchetState(current.state);
      const { plaintext } = ratchetDecrypt({ ...args, state });
      out = { plaintext };
      return { version: current.version + 1, state };
    });
    if (!out) throw new Error("Unexpected: missing decrypt output");
    return out;
  }

  const record = await store.load(sessionId);
  if (!record) throw new SessionNotFoundError();
  const state = cloneRatchetState(record.state);
  const { plaintext } = ratchetDecrypt({ ...args, state });
  await store.save(sessionId, { version: record.version + 1, state });
  return { plaintext };
}

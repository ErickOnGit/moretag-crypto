import { ratchetEncrypt, ratchetDecrypt, type RatchetState } from "./ratchet.js";

export interface PersistedSession {
  version: number;
  state: RatchetState;
}

export interface RatchetSessionStore {
  load(sessionId: string): Promise<PersistedSession | undefined> | PersistedSession | undefined;
  save(sessionId: string, record: PersistedSession): Promise<void> | void;
  transact?(
    sessionId: string,
    fn: (current: PersistedSession) => PersistedSession
  ): Promise<PersistedSession> | PersistedSession;
}

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
    if (!current) throw new Error(`Session not found: ${sessionId}`);
    const next = fn(current);
    this.save(sessionId, next);
    return next;
  }
}

export async function ratchetEncryptWithStore(
  store: RatchetSessionStore,
  sessionId: string,
  args: Parameters<typeof ratchetEncrypt>[0]
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
  if (!record) throw new Error(`Session not found: ${sessionId}`);
  const state = cloneRatchetState(record.state);
  const { header, ciphertext_b64 } = ratchetEncrypt({ ...args, state });
  await store.save(sessionId, { version: record.version + 1, state });
  return { header, ciphertext_b64 };
}

export async function ratchetDecryptWithStore(
  store: RatchetSessionStore,
  sessionId: string,
  args: Parameters<typeof ratchetDecrypt>[0]
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
  if (!record) throw new Error(`Session not found: ${sessionId}`);
  const state = cloneRatchetState(record.state);
  const { plaintext } = ratchetDecrypt({ ...args, state });
  await store.save(sessionId, { version: record.version + 1, state });
  return { plaintext };
}

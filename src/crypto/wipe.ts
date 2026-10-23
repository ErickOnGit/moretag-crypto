/**
 * Best-effort erasure of secret bytes this library created.
 *
 * JavaScript promises nothing here: an engine may have copied the bytes (a
 * garbage collector moving a buffer, a JIT keeping a value in a register, a
 * crypto provider's own internal copies, a string made from them), so wiping
 * shortens how long a secret sits in memory; it does not prove it is gone.
 *
 * The library wipes only arrays it created within the same call (DH outputs, the
 * X3DH key material, the ephemeral private key, replaced root and chain keys of
 * its own working copy, message keys, evicted skipped keys, a failed decrypt's
 * working copy). It never wipes an array it received from a caller or a store.
 */
export function wipe(...arrays: Array<Uint8Array | null | undefined>): void {
  for (const a of arrays) a?.fill(0);
}

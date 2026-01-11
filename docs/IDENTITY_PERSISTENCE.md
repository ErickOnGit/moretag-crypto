# Identity Key Persistence Guide

## Overview

`X3DHPrekeyManagerV1` generates identity keys in memory but does NOT persist them. Applications must implement secure storage for long-term identity management.

Without proper persistence:
- Users lose their identity on app restart
- Cannot decrypt old messages
- Break session continuity with peers
- Need to re-publish prekey bundles

## Storage Requirements

Identity keys consist of:

| Key Type | Algorithm | Private Key | Public Key | Purpose |
|----------|-----------|-------------|------------|---------|
| DH Identity Key | X25519 | `ik.priv32` (32 bytes) | `ik.pub32` (32 bytes) | Key agreement in X3DH |
| Signing Identity Key | Ed25519 | `ik_sig.priv32` (32 bytes) | `ik_sig.pub32` (32 bytes) | Signing prekey bundles |

⚠️ **Critical**: Private keys MUST be stored encrypted unless using hardware-backed storage (e.g., iOS Keychain, Android KeyStore, TPM).

## Example 1: Encrypted JSON File

Best for: Node.js applications, desktop apps, servers

```typescript
import { randomBytes } from '@noble/ciphers/utils';
import { xchacha20poly1305 } from '@noble/ciphers/chacha';
import { scrypt } from '@noble/hashes/scrypt';
import { readFileSync, writeFileSync, existsSync } from 'fs';
import { bytesToBase64, base64ToBytes } from '../encoding/base64.js';
import { X3DHPrekeyManagerV1 } from '../x3dh/prekey-manager.js';

interface StoredIdentity {
  version: 1;
  device_id: string;
  encrypted_payload_b64: string;
  nonce_b64: string;
  salt_b64: string;
}

interface IdentityPayload {
  ik_priv32_b64: string;
  ik_pub32_b64: string;
  ik_sig_priv32_b64: string;
  ik_sig_pub32_b64: string;
  created_at: number;
}

/**
 * Save identity to encrypted JSON file.
 * Uses scrypt for password-based key derivation and XChaCha20-Poly1305 for encryption.
 */
export async function saveIdentity(
  deviceId: string,
  manager: X3DHPrekeyManagerV1,
  password: string,
  filePath: string
): Promise<void> {
  if (!password || password.length < 12) {
    throw new Error('Password must be at least 12 characters');
  }
  
  const salt = randomBytes(32);
  const nonce = randomBytes(24);
  
  // Derive encryption key from password using scrypt
  // N=2^17 provides strong security while remaining practical
  const key = scrypt(password, salt, { N: 2**17, r: 8, p: 1, dkLen: 32 });
  
  const payload: IdentityPayload = {
    ik_priv32_b64: bytesToBase64(manager.ik.priv32),
    ik_pub32_b64: bytesToBase64(manager.ik.pub32),
    ik_sig_priv32_b64: bytesToBase64(manager.ik_sig.priv32),
    ik_sig_pub32_b64: bytesToBase64(manager.ik_sig.pub32),
    created_at: Date.now(),
  };
  
  const plaintext = new TextEncoder().encode(JSON.stringify(payload));
  const cipher = xchacha20poly1305(key, nonce);
  const ciphertext = cipher.encrypt(plaintext);
  
  const stored: StoredIdentity = {
    version: 1,
    device_id: deviceId,
    encrypted_payload_b64: bytesToBase64(ciphertext),
    nonce_b64: bytesToBase64(nonce),
    salt_b64: bytesToBase64(salt),
  };
  
  // Write with restrictive permissions (owner read/write only)
  writeFileSync(filePath, JSON.stringify(stored, null, 2), { mode: 0o600 });
  
  console.log(`Identity saved to ${filePath} (encrypted)`);
}

/**
 * Load identity from encrypted JSON file.
 */
export async function loadIdentity(
  password: string,
  filePath: string
): Promise<X3DHPrekeyManagerV1> {
  if (!existsSync(filePath)) {
    throw new Error(`Identity file not found: ${filePath}`);
  }
  
  const stored: StoredIdentity = JSON.parse(readFileSync(filePath, 'utf-8'));
  
  if (stored.version !== 1) {
    throw new Error(`Unsupported identity version: ${stored.version}`);
  }
  
  const salt = base64ToBytes(stored.salt_b64);
  const nonce = base64ToBytes(stored.nonce_b64);
  const ciphertext = base64ToBytes(stored.encrypted_payload_b64);
  
  // Derive same key from password
  const key = scrypt(password, salt, { N: 2**17, r: 8, p: 1, dkLen: 32 });
  
  const cipher = xchacha20poly1305(key, nonce);
  
  let plaintext: Uint8Array;
  try {
    plaintext = cipher.decrypt(ciphertext);
  } catch (err) {
    throw new Error('Failed to decrypt identity (incorrect password or corrupted file)');
  }
  
  const payload: IdentityPayload = JSON.parse(new TextDecoder().decode(plaintext));
  
  return new X3DHPrekeyManagerV1({
    recipient_device_id: stored.device_id,
    ik: {
      priv32: base64ToBytes(payload.ik_priv32_b64),
      pub32: base64ToBytes(payload.ik_pub32_b64),
    },
    ik_sig: {
      priv32: base64ToBytes(payload.ik_sig_priv32_b64),
      pub32: base64ToBytes(payload.ik_sig_pub32_b64),
    },
  });
}

/**
 * Check if identity file exists.
 */
export function identityExists(filePath: string): boolean {
  return existsSync(filePath);
}
```

### Usage Example

```typescript
import { saveIdentity, loadIdentity, identityExists } from './identity-store';
import { X3DHPrekeyManagerV1 } from 'moretag-crypto';

const deviceId = 'alice-device-001';
const identityPath = './data/identity.enc.json';
const password = process.env.IDENTITY_PASSWORD; // From secure source

let manager: X3DHPrekeyManagerV1;

if (identityExists(identityPath)) {
  // Load existing identity
  manager = await loadIdentity(password, identityPath);
  console.log('Loaded existing identity');
} else {
  // Create new identity
  manager = new X3DHPrekeyManagerV1({ recipient_device_id: deviceId });
  await saveIdentity(deviceId, manager, password, identityPath);
  console.log('Created new identity');
}

// Now use manager for X3DH operations
manager.rotateSignedPrekey(Date.now());
manager.addOneTimePrekeys({ startId: 1, count: 100 });
```

## Example 2: OS Keychain (macOS/iOS)

Best for: Electron apps, native macOS/iOS applications

### Using Electron's safeStorage

```typescript
import { safeStorage } from 'electron';
import { app } from 'electron';
import { readFileSync, writeFileSync, existsSync } from 'fs';
import { join } from 'path';
import { bytesToBase64, base64ToBytes } from '../encoding/base64.js';
import { X3DHPrekeyManagerV1 } from '../x3dh/prekey-manager.js';

interface KeychainIdentity {
  version: 1;
  device_id: string;
  encrypted_data: string; // Base64-encoded encrypted buffer
}

/**
 * Save identity to OS keychain via Electron's safeStorage.
 * On macOS, this uses the Keychain Access system.
 */
export async function saveToKeychain(
  deviceId: string,
  manager: X3DHPrekeyManagerV1
): Promise<void> {
  if (!safeStorage.isEncryptionAvailable()) {
    throw new Error('OS-level encryption not available');
  }
  
  const payload = {
    ik_priv32_b64: bytesToBase64(manager.ik.priv32),
    ik_pub32_b64: bytesToBase64(manager.ik.pub32),
    ik_sig_priv32_b64: bytesToBase64(manager.ik_sig.priv32),
    ik_sig_pub32_b64: bytesToBase64(manager.ik_sig.pub32),
    created_at: Date.now(),
  };
  
  const plaintext = JSON.stringify(payload);
  const encrypted = safeStorage.encryptString(plaintext);
  
  const keychainData: KeychainIdentity = {
    version: 1,
    device_id: deviceId,
    encrypted_data: encrypted.toString('base64'),
  };
  
  // Store in app's user data directory
  const identityPath = join(app.getPath('userData'), 'identity.keychain.json');
  writeFileSync(identityPath, JSON.stringify(keychainData, null, 2), { mode: 0o600 });
  
  console.log(`Identity saved to keychain (${identityPath})`);
}

/**
 * Load identity from OS keychain.
 */
export async function loadFromKeychain(deviceId: string): Promise<X3DHPrekeyManagerV1> {
  const identityPath = join(app.getPath('userData'), 'identity.keychain.json');
  
  if (!existsSync(identityPath)) {
    throw new Error('Identity not found in keychain');
  }
  
  const keychainData: KeychainIdentity = JSON.parse(readFileSync(identityPath, 'utf-8'));
  
  if (keychainData.version !== 1) {
    throw new Error(`Unsupported keychain identity version: ${keychainData.version}`);
  }
  
  if (keychainData.device_id !== deviceId) {
    throw new Error('Device ID mismatch');
  }
  
  const encryptedBuffer = Buffer.from(keychainData.encrypted_data, 'base64');
  const plaintext = safeStorage.decryptString(encryptedBuffer);
  const payload = JSON.parse(plaintext);
  
  return new X3DHPrekeyManagerV1({
    recipient_device_id: deviceId,
    ik: {
      priv32: base64ToBytes(payload.ik_priv32_b64),
      pub32: base64ToBytes(payload.ik_pub32_b64),
    },
    ik_sig: {
      priv32: base64ToBytes(payload.ik_sig_priv32_b64),
      pub32: base64ToBytes(payload.ik_sig_pub32_b64),
    },
  });
}
```

### Using Native Keychain API (macOS)

For non-Electron native apps, use native bindings like `keytar`:

```typescript
import * as keytar from 'keytar';
import { bytesToBase64, base64ToBytes } from '../encoding/base64.js';

const SERVICE_NAME = 'moretag-crypto';

export async function saveToNativeKeychain(
  deviceId: string,
  manager: X3DHPrekeyManagerV1
): Promise<void> {
  const payload = {
    ik_priv32_b64: bytesToBase64(manager.ik.priv32),
    ik_pub32_b64: bytesToBase64(manager.ik.pub32),
    ik_sig_priv32_b64: bytesToBase64(manager.ik_sig.priv32),
    ik_sig_pub32_b64: bytesToBase64(manager.ik_sig.pub32),
    created_at: Date.now(),
  };
  
  await keytar.setPassword(
    SERVICE_NAME,
    `identity.${deviceId}`,
    JSON.stringify(payload)
  );
}

export async function loadFromNativeKeychain(deviceId: string): Promise<X3DHPrekeyManagerV1> {
  const payload = await keytar.getPassword(SERVICE_NAME, `identity.${deviceId}`);
  
  if (!payload) {
    throw new Error('Identity not found in keychain');
  }
  
  const data = JSON.parse(payload);
  
  return new X3DHPrekeyManagerV1({
    recipient_device_id: deviceId,
    ik: {
      priv32: base64ToBytes(data.ik_priv32_b64),
      pub32: base64ToBytes(data.ik_pub32_b64),
    },
    ik_sig: {
      priv32: base64ToBytes(data.ik_sig_priv32_b64),
      pub32: base64ToBytes(data.ik_sig_pub32_b64),
    },
  });
}
```

## Example 3: Browser IndexedDB

Best for: Web applications, Progressive Web Apps

```typescript
import { openDB, DBSchema, IDBPDatabase } from 'idb';
import { bytesToBase64, base64ToBytes } from '../encoding/base64.js';
import { X3DHPrekeyManagerV1 } from '../x3dh/prekey-manager.js';

interface IdentityDB extends DBSchema {
  identities: {
    key: string; // device_id
    value: {
      device_id: string;
      encrypted_data: ArrayBuffer;
      iv: number[];
      salt: number[];
      created_at: number;
    };
  };
}

/**
 * Save identity to IndexedDB with Web Crypto API encryption.
 */
export async function saveToIndexedDB(
  deviceId: string,
  manager: X3DHPrekeyManagerV1,
  password: string
): Promise<void> {
  const db = await openDB<IdentityDB>('moretag-identities', 1, {
    upgrade(db) {
      db.createObjectStore('identities', { keyPath: 'device_id' });
    },
  });
  
  // Derive key from password using PBKDF2
  const passwordKey = await window.crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(password),
    'PBKDF2',
    false,
    ['deriveBits', 'deriveKey']
  );
  
  const salt = crypto.getRandomValues(new Uint8Array(32));
  
  const encryptionKey = await window.crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations: 100000,
      hash: 'SHA-256',
    },
    passwordKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt']
  );
  
  const payload = JSON.stringify({
    ik_priv32_b64: bytesToBase64(manager.ik.priv32),
    ik_pub32_b64: bytesToBase64(manager.ik.pub32),
    ik_sig_priv32_b64: bytesToBase64(manager.ik_sig.priv32),
    ik_sig_pub32_b64: bytesToBase64(manager.ik_sig.pub32),
    created_at: Date.now(),
  });
  
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await window.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    encryptionKey,
    new TextEncoder().encode(payload)
  );
  
  await db.put('identities', {
    device_id: deviceId,
    encrypted_data: ciphertext,
    iv: Array.from(iv),
    salt: Array.from(salt),
    created_at: Date.now(),
  });
  
  console.log('Identity saved to IndexedDB');
}

/**
 * Load identity from IndexedDB.
 */
export async function loadFromIndexedDB(
  deviceId: string,
  password: string
): Promise<X3DHPrekeyManagerV1> {
  const db = await openDB<IdentityDB>('moretag-identities', 1);
  
  const stored = await db.get('identities', deviceId);
  if (!stored) {
    throw new Error('Identity not found');
  }
  
  // Derive key from password
  const passwordKey = await window.crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(password),
    'PBKDF2',
    false,
    ['deriveBits', 'deriveKey']
  );
  
  const encryptionKey = await window.crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: new Uint8Array(stored.salt),
      iterations: 100000,
      hash: 'SHA-256',
    },
    passwordKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );
  
  const plaintext = await window.crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: new Uint8Array(stored.iv) },
    encryptionKey,
    stored.encrypted_data
  );
  
  const payload = JSON.parse(new TextDecoder().decode(plaintext));
  
  return new X3DHPrekeyManagerV1({
    recipient_device_id: deviceId,
    ik: {
      priv32: base64ToBytes(payload.ik_priv32_b64),
      pub32: base64ToBytes(payload.ik_pub32_b64),
    },
    ik_sig: {
      priv32: base64ToBytes(payload.ik_sig_priv32_b64),
      pub32: base64ToBytes(payload.ik_sig_pub32_b64),
    },
  });
}
```

## Key Rotation

Identity key rotation is rare but necessary in these scenarios:
- Key compromise detected
- Cryptographic vulnerability discovered
- Device ownership transfer
- Security policy compliance (e.g., yearly rotation)

### Rotation Strategy

```typescript
interface IdentityVersion {
  version: number;
  manager: X3DHPrekeyManagerV1;
  createdAt: number;
  validUntil: number; // Grace period for in-flight messages
  status: 'active' | 'retiring' | 'retired';
}

export class IdentityStore {
  private identities: Map<number, IdentityVersion> = new Map();
  private currentVersion: number = 0;
  
  /**
   * Rotate to new identity keys.
   * Keeps old identity accessible during grace period.
   */
  async rotate(
    deviceId: string,
    gracePeriodDays: number = 7
  ): Promise<X3DHPrekeyManagerV1> {
    const newVersion = this.currentVersion + 1;
    const newManager = new X3DHPrekeyManagerV1({ recipient_device_id: deviceId });
    
    const gracePeriodMs = gracePeriodDays * 24 * 60 * 60 * 1000;
    
    // Add new identity
    this.identities.set(newVersion, {
      version: newVersion,
      manager: newManager,
      createdAt: Date.now(),
      validUntil: Infinity, // Active indefinitely until next rotation
      status: 'active',
    });
    
    // Mark old identity as retiring
    if (this.identities.has(this.currentVersion)) {
      const old = this.identities.get(this.currentVersion)!;
      old.status = 'retiring';
      old.validUntil = Date.now() + gracePeriodMs;
    }
    
    this.currentVersion = newVersion;
    
    // Persist new identity
    await this.saveAllVersions();
    
    console.log(`Rotated to identity version ${newVersion}`);
    return newManager;
  }
  
  /**
   * Get the current active identity.
   */
  getCurrent(): X3DHPrekeyManagerV1 {
    const identity = this.identities.get(this.currentVersion);
    if (!identity) {
      throw new Error('No active identity');
    }
    return identity.manager;
  }
  
  /**
   * Get identity by version (for decrypting old messages).
   */
  getVersion(version: number): X3DHPrekeyManagerV1 | undefined {
    const identity = this.identities.get(version);
    if (!identity) return undefined;
    
    if (identity.status === 'retired') {
      console.warn(`Identity version ${version} is retired`);
      return undefined;
    }
    
    return identity.manager;
  }
  
  /**
   * Clean up expired identities.
   */
  pruneExpired(): void {
    const now = Date.now();
    
    for (const [version, identity] of this.identities) {
      if (identity.status === 'retiring' && identity.validUntil < now) {
        identity.status = 'retired';
        console.log(`Identity version ${version} retired`);
      }
      
      // Actually delete retired identities after additional safety period
      if (identity.status === 'retired' && identity.validUntil + 30 * 24 * 60 * 60 * 1000 < now) {
        this.identities.delete(version);
        console.log(`Identity version ${version} permanently deleted`);
      }
    }
  }
  
  private async saveAllVersions(): Promise<void> {
    // Implementation depends on storage backend
    // Should save all non-retired identities with version numbers
  }
}
```

### Rotation Workflow

```typescript
async function performIdentityRotation(
  store: IdentityStore,
  prekeyServer: PrekeyServer,
  deviceId: string
): Promise<void> {
  console.log('Starting identity rotation...');
  
  // 1. Generate new identity
  const newManager = await store.rotate(deviceId, 7);
  
  // 2. Generate new prekeys
  newManager.rotateSignedPrekey(Date.now());
  newManager.addOneTimePrekeys({ startId: 1, count: 100 });
  
  // 3. Publish new prekey bundle to server
  const newBundle = newManager.getPrekeyBundle();
  await prekeyServer.publishBundle(deviceId, newBundle);
  
  // 4. Notify peers about identity change (optional but recommended)
  await notifyPeersOfRotation(deviceId, newManager.ik.pub32);
  
  // 5. Mark all active sessions for re-initialization
  await markSessionsForRekey(deviceId);
  
  console.log('Identity rotation complete');
}
```

## Backup and Recovery

### Encrypted Backup File

Generate a backup that users can save externally:

```typescript
import { randomBytes } from '@noble/ciphers/utils';
import { xchacha20poly1305 } from '@noble/ciphers/chacha';
import { scrypt } from '@noble/hashes/scrypt';
import { bytesToBase64 } from '../encoding/base64.js';

/**
 * Create encrypted backup blob.
 * Returns base64-encoded string that user can save.
 */
export async function createBackup(
  manager: X3DHPrekeyManagerV1,
  backupPassword: string
): Promise<string> {
  if (backupPassword.length < 16) {
    throw new Error('Backup password must be at least 16 characters');
  }
  
  // Use stronger parameters for backup encryption
  const salt = randomBytes(32);
  const nonce = randomBytes(24);
  const key = scrypt(backupPassword, salt, { N: 2**18, r: 8, p: 1, dkLen: 32 });
  
  const payload = {
    ik_priv32_b64: bytesToBase64(manager.ik.priv32),
    ik_pub32_b64: bytesToBase64(manager.ik.pub32),
    ik_sig_priv32_b64: bytesToBase64(manager.ik_sig.priv32),
    ik_sig_pub32_b64: bytesToBase64(manager.ik_sig.pub32),
    device_id: manager.recipient_device_id,
    backup_created_at: Date.now(),
  };
  
  const plaintext = new TextEncoder().encode(JSON.stringify(payload));
  const cipher = xchacha20poly1305(key, nonce);
  const ciphertext = cipher.encrypt(plaintext);
  
  const backup = {
    version: 1,
    type: 'moretag-identity-backup',
    salt_b64: bytesToBase64(salt),
    nonce_b64: bytesToBase64(nonce),
    ciphertext_b64: bytesToBase64(ciphertext),
  };
  
  return bytesToBase64(new TextEncoder().encode(JSON.stringify(backup)));
}

/**
 * Restore identity from backup blob.
 */
export async function restoreFromBackup(
  backupBlob: string,
  backupPassword: string
): Promise<X3DHPrekeyManagerV1> {
  const backupJson = new TextDecoder().decode(base64ToBytes(backupBlob));
  const backup = JSON.parse(backupJson);
  
  if (backup.version !== 1 || backup.type !== 'moretag-identity-backup') {
    throw new Error('Invalid backup format');
  }
  
  const salt = base64ToBytes(backup.salt_b64);
  const nonce = base64ToBytes(backup.nonce_b64);
  const ciphertext = base64ToBytes(backup.ciphertext_b64);
  
  const key = scrypt(backupPassword, salt, { N: 2**18, r: 8, p: 1, dkLen: 32 });
  const cipher = xchacha20poly1305(key, nonce);
  
  try {
    const plaintext = cipher.decrypt(ciphertext);
    const payload = JSON.parse(new TextDecoder().decode(plaintext));
    
    return new X3DHPrekeyManagerV1({
      recipient_device_id: payload.device_id,
      ik: {
        priv32: base64ToBytes(payload.ik_priv32_b64),
        pub32: base64ToBytes(payload.ik_pub32_b64),
      },
      ik_sig: {
        priv32: base64ToBytes(payload.ik_sig_priv32_b64),
        pub32: base64ToBytes(payload.ik_sig_pub32_b64),
      },
    });
  } catch (err) {
    throw new Error('Failed to restore backup (incorrect password or corrupted backup)');
  }
}
```

### Recovery Codes (BIP39-style)

For user-friendly backup, generate recovery codes:

```typescript
import { generateMnemonic, mnemonicToSeedSync, validateMnemonic } from 'bip39';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha2';

/**
 * Generate recovery mnemonic (24 words).
 * IMPORTANT: This is illustrative - using key material as entropy for BIP39
 * may not follow best practices. Consider domain separation.
 */
export function generateRecoveryMnemonic(manager: X3DHPrekeyManagerV1): string {
  // Combine key material as entropy (256 bits)
  const entropy = new Uint8Array(32);
  entropy.set(manager.ik.priv32.slice(0, 16), 0);
  entropy.set(manager.ik_sig.priv32.slice(0, 16), 16);
  
  // Derive deterministic seed
  const seed = hkdf(sha256, entropy, new Uint8Array(32), new Uint8Array(0), 32);
  
  // Generate mnemonic from seed
  return generateMnemonic(Array.from(seed).map(b => b.toString(16).padStart(2, '0')).join(''));
}

/**
 * Restore identity from recovery mnemonic.
 */
export function restoreFromMnemonic(
  mnemonic: string,
  deviceId: string
): X3DHPrekeyManagerV1 {
  if (!validateMnemonic(mnemonic)) {
    throw new Error('Invalid recovery mnemonic');
  }
  
  const seed = mnemonicToSeedSync(mnemonic);
  
  // Derive identity keys from seed
  const ikPriv = hkdf(sha256, seed, new Uint8Array(0), new TextEncoder().encode('ik'), 32);
  const ikSigPriv = hkdf(sha256, seed, new Uint8Array(0), new TextEncoder().encode('ik_sig'), 32);
  
  // This is simplified - real implementation should properly derive public keys
  // from private keys using the respective curve operations
  
  throw new Error('Mnemonic recovery not fully implemented - use backup blobs instead');
}
```

## Security Considerations

### 1. Memory Safety

JavaScript cannot reliably wipe memory. Mitigations:

```typescript
// Minimize key lifetime in memory
async function processWithEphemeralKey(password: string, action: (manager: X3DHPrekeyManagerV1) => Promise<void>) {
  const manager = await loadIdentity(password, './identity.enc.json');
  
  try {
    await action(manager);
  } finally {
    // Best effort: overwrite key material
    // Note: JavaScript engines may have copied these elsewhere
    if (manager.ik?.priv32) manager.ik.priv32.fill(0);
    if (manager.ik_sig?.priv32) manager.ik_sig.priv32.fill(0);
  }
}
```

### 2. File Permissions

Always use restrictive permissions on identity files:

```typescript
import { chmodSync } from 'fs';

function saveWithSecurePermissions(filePath: string, data: string): void {
  writeFileSync(filePath, data);
  chmodSync(filePath, 0o600); // Owner read/write only
}
```

### 3. Key Derivation Parameters

Choose appropriate parameters based on threat model:

| Use Case | Algorithm | Parameters | Time (approx) |
|----------|-----------|------------|---------------|
| Primary storage | scrypt | N=2^17, r=8, p=1 | ~100ms |
| Backup encryption | scrypt | N=2^18, r=8, p=1 | ~200ms |
| High security | scrypt | N=2^20, r=8, p=1 | ~800ms |

### 4. Backup Security

Backups must be MORE secure than primary storage:

```typescript
// ✅ Good: Separate, stronger password for backups
const primaryPassword = getUserPassword();
const backupPassword = getBackupPassword(); // Different, stronger

// ❌ Bad: Same password, same parameters
await saveIdentity(device, manager, password, './identity.json');
await createBackup(manager, password); // Reusing password
```

### 5. Transport Security

Never transmit private keys without additional encryption:

```typescript
// ❌ NEVER do this
async function dangerousSync(manager: X3DHPrekeyManagerV1) {
  await fetch('/api/sync', {
    method: 'POST',
    body: JSON.stringify({
      ik_priv: bytesToBase64(manager.ik.priv32), // DANGEROUS
    }),
  });
}

// ✅ If sync is necessary, use end-to-end encryption
async function secureSync(manager: X3DHPrekeyManagerV1, peerPubKey: Uint8Array) {
  const encryptedBackup = await encryptForPeer(manager, peerPubKey);
  await fetch('/api/sync', {
    method: 'POST',
    body: encryptedBackup,
  });
}
```

## Testing Identity Persistence

```typescript
import { describe, it, expect } from 'vitest';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

describe('Identity Persistence', () => {
  it('round-trips identity through encrypted file', async () => {
    const tempDir = mkdtempSync(join(tmpdir(), 'identity-test-'));
    const identityPath = join(tempDir, 'identity.enc.json');
    
    try {
      const deviceId = 'test-device-001';
      const password = 'secure-password-123';
      
      // Create and save
      const original = new X3DHPrekeyManagerV1({ recipient_device_id: deviceId });
      await saveIdentity(deviceId, original, password, identityPath);
      
      // Load and verify
      const restored = await loadIdentity(password, identityPath);
      expect(restored.recipient_device_id).toBe(deviceId);
      expect(restored.ik.pub32).toEqual(original.ik.pub32);
      expect(restored.ik_sig.pub32).toEqual(original.ik_sig.pub32);
      
      // Verify private keys work (sign something)
      original.rotateSignedPrekey(1);
      restored.rotateSignedPrekey(1);
      const origBundle = original.getPrekeyBundle();
      const restBundle = restored.getPrekeyBundle();
      expect(restBundle.spk_sig_b64).toBe(origBundle.spk_sig_b64);
      
    } finally {
      rmSync(tempDir, { recursive: true, force: true });
    }
  });
  
  it('rejects incorrect password', async () => {
    const tempDir = mkdtempSync(join(tmpdir(), 'identity-test-'));
    const identityPath = join(tempDir, 'identity.enc.json');
    
    try {
      const manager = new X3DHPrekeyManagerV1({ recipient_device_id: 'test' });
      await saveIdentity('test', manager, 'correct-password', identityPath);
      
      await expect(
        loadIdentity('wrong-password', identityPath)
      ).rejects.toThrow(/incorrect password/i);
      
    } finally {
      rmSync(tempDir, { recursive: true, force: true });
    }
  });
});
```

## Production Checklist

Before deploying identity persistence:

- [ ] Choose appropriate storage backend for platform
- [ ] Implement strong password requirements (min 12 chars)
- [ ] Use secure key derivation parameters (scrypt N≥2^17)
- [ ] Set restrictive file permissions (0o600)
- [ ] Implement backup creation and restore
- [ ] Test password change workflow
- [ ] Document recovery procedure for users
- [ ] Plan key rotation policy
- [ ] Implement audit logging for key operations
- [ ] Test restore from backup on clean device

## See Also

- [X3DHPrekeyManagerV1 API](../README.md#x3dh-prekey-lifecycle)
- [THREAT_MODEL.md](./THREAT_MODEL.md) - Security assumptions
- [SESSION_ID_GUIDELINES.md](./SESSION_ID_GUIDELINES.md) - Session management
- [PREKEY_ROTATION.md](./PREKEY_ROTATION.md) - Prekey lifecycle

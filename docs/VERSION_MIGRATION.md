# Protocol Version Migration Strategy

## Overview

moretag-crypto follows a dual versioning approach:
- **NPM package version** (semantic versioning)
- **Protocol version** (wire format compatibility)

This document defines strategies for handling protocol upgrades, ensuring smooth transitions, and maintaining backward compatibility during migration periods.

## Versioning Principles

### Package Version (semver)

```
1.0.0 → 1.x.x  # Backward-compatible features, bug fixes
1.x.x → 2.0.0  # Breaking API changes
```

- Patch (1.0.x): Bug fixes, internal improvements
- Minor (1.x.0): New features, backward-compatible changes
- Major (x.0.0): Breaking changes to public API

### Protocol Version

```typescript
// All wire formats include version field
interface HeaderProtoV1 {
  v: 1;  // Protocol version
  alg: string;
  // ... other fields
}

interface X3DHPrekeyBundleV1 {
  v: 1;  // Protocol version
  alg: string;
  // ... other fields
}
```

- Protocol version increments independently of package version
- v1 protocol is **frozen** (see [SPEC.md](./SPEC.md))
- Wire format changes require new protocol version
- Cryptographic algorithm changes require new protocol version

## Version Compatibility Matrix

| Client Version | Can Read v1 | Can Read v2 | Can Write v1 | Can Write v2 |
|----------------|-------------|-------------|--------------|--------------|
| v1.x.x         | ✅          | ❌          | ✅           | ❌           |
| v2.0.0-2.x.x   | ✅          | ✅          | ⚠️ Deprecated | ✅          |
| v3.0.0+        | ❌          | ✅          | ❌           | ✅           |

**Legend**:
- ✅ Fully supported
- ⚠️ Supported but deprecated (warnings logged)
- ❌ Not supported

## Handling Protocol Upgrades

### Scenario 1: Application Upgrade (v1 client → v2 client)

When upgrading the moretag-crypto library from v1 to v2:

```typescript
import { FileRatchetStore } from 'moretag-crypto';

// v2 library can read v1 persisted sessions
async function handleExistingSessions(store: FileRatchetStore) {
  const allSessions = store.listAll();
  
  for (const sessionId of allSessions) {
    const session = store.load(sessionId);
    
    if (!session) continue;
    
    if (session.state.version === 1) {
      console.log(`Session ${sessionId} uses v1 protocol`);
      // Continue using v1 for this session
      // New sessions will use v2
    } else if (session.state.version === 2) {
      console.log(`Session ${sessionId} uses v2 protocol`);
      // Use v2 APIs
    }
  }
}
```

**Migration Options**:

**Option A: Gradual Migration (Recommended)**
```typescript
class SessionManager {
  /**
   * Upgrade sessions naturally as they re-key.
   */
  async handleRekey(oldSessionId: string): Promise<string> {
    const oldSession = await this.store.load(oldSessionId);
    
    if (oldSession.state.version === 1) {
      console.log('Upgrading session to v2 during rekey');
      
      // Perform fresh X3DH handshake with v2
      const newSessionId = await this.initializeV2Session(/* ... */);
      
      // Archive old session
      await this.archiveSession(oldSessionId, 7); // 7 day grace period
      
      return newSessionId;
    }
    
    return oldSessionId; // Already v2
  }
}
```

**Option B: Forced Migration**
```typescript
async function forceUpgradeAll(
  store: FileRatchetStore,
  peerDirectory: PeerDirectory
): Promise<void> {
  console.log('Starting forced protocol upgrade');
  
  const allSessions = store.listAll();
  const upgraded: string[] = [];
  
  for (const oldSessionId of allSessions) {
    const session = store.load(oldSessionId);
    if (!session || session.state.version !== 1) continue;
    
    try {
      // Get peer info
      const peer = await peerDirectory.lookup(session.theirDeviceId);
      
      if (!peer.supportsProtocolV2) {
        console.warn(`Peer ${peer.deviceId} doesn't support v2 yet`);
        continue;
      }
      
      // Send notification
      await sendUpgradeNotification(oldSessionId);
      
      // Perform fresh handshake
      const newSessionId = await initializeV2Session(peer);
      
      // Archive old
      await archiveSession(oldSessionId);
      
      upgraded.push(newSessionId);
    } catch (err) {
      console.error(`Failed to upgrade session ${oldSessionId}:`, err);
    }
  }
  
  console.log(`Upgraded ${upgraded.length}/${allSessions.length} sessions`);
}
```

### Scenario 2: Peer Version Mismatch

Alice (v2 client) wants to message Bob (v1 client):

```typescript
interface PeerCapabilities {
  device_id: string;
  supported_protocols: number[]; // e.g., [1] or [1, 2] or [2]
  preferred_protocol: number;
  library_version: string;
}

class ProtocolNegotiator {
  /**
   * Select highest common protocol version.
   */
  async selectProtocol(
    myCapabilities: PeerCapabilities,
    theirCapabilities: PeerCapabilities
  ): Promise<number> {
    // Find intersection of supported protocols
    const common = myCapabilities.supported_protocols.filter(v =>
      theirCapabilities.supported_protocols.includes(v)
    );
    
    if (common.length === 0) {
      throw new Error(
        `No compatible protocol version between ` +
        `${myCapabilities.device_id} (supports ${myCapabilities.supported_protocols}) and ` +
        `${theirCapabilities.device_id} (supports ${theirCapabilities.supported_protocols})`
      );
    }
    
    // Use highest common version
    const selected = Math.max(...common);
    console.log(`Selected protocol v${selected} for session`);
    return selected;
  }
  
  /**
   * Initialize session with negotiated protocol.
   */
  async initializeSession(
    myCapabilities: PeerCapabilities,
    theirCapabilities: PeerCapabilities,
    theirBundle: any
  ): Promise<any> {
    const protocol = await this.selectProtocol(myCapabilities, theirCapabilities);
    
    if (protocol === 1) {
      // Use v1 APIs
      return x3dhInitiatorV1({
        sender_device_id: myCapabilities.device_id,
        recipient_bundle: theirBundle as X3DHPrekeyBundleV1,
        initiator_ik_priv32: this.getIdentityKey(),
      });
    } else if (protocol === 2) {
      // Use v2 APIs (hypothetical)
      return x3dhInitiatorV2({
        sender_device_id: myCapabilities.device_id,
        recipient_bundle: theirBundle as X3DHPrekeyBundleV2,
        initiator_ik_priv32: this.getIdentityKey(),
      });
    } else {
      throw new Error(`Unsupported protocol version: ${protocol}`);
    }
  }
}
```

## Migration Timeline (When v2 Arrives)

### Phase 1: Dual-Support (Months 0-12)

**v2.0.0 Release**:
```typescript
// New v2 library supports both protocols
export {
  // v1 APIs (maintained for compatibility)
  x3dhInitiatorV1,
  x3dhResponderV1,
  // v2 APIs (new)
  x3dhInitiatorV2,
  x3dhResponderV2,
};

// Default to v2 for new sessions
const DEFAULT_PROTOCOL_VERSION = 2;

// But support v1 for existing sessions
function detectProtocolVersion(bundle: any): 1 | 2 {
  return bundle.v || 1;
}
```

**Activities**:
- Default to v2 for new sessions
- Fall back to v1 when communicating with v1-only peers
- Log usage metrics for v1 vs v2 adoption
- Monitor for compatibility issues

**Metrics to Track**:
```typescript
interface ProtocolMetrics {
  v1_sessions_active: number;
  v2_sessions_active: number;
  v1_messages_sent: number;
  v2_messages_sent: number;
  fallback_to_v1_count: number;
  negotiation_failures: number;
}

async function collectProtocolMetrics(): Promise<ProtocolMetrics> {
  // Implementation depends on your analytics system
  return {
    v1_sessions_active: await countSessionsByVersion(1),
    v2_sessions_active: await countSessionsByVersion(2),
    v1_messages_sent: await countMessagesByProtocol(1),
    v2_messages_sent: await countMessagesByProtocol(2),
    fallback_to_v1_count: await countFallbacks(),
    negotiation_failures: await countNegotiationFailures(),
  };
}
```

### Phase 2: Deprecation Warning (Months 12-18)

**v2.5.0 Release**:
```typescript
// Add deprecation warnings for v1 API usage
function x3dhInitiatorV1(args: any) {
  console.warn(
    'DEPRECATION WARNING: x3dhInitiatorV1 is deprecated and will be removed in v3.0.0. ' +
    'Please upgrade to x3dhInitiatorV2. See: https://docs.example.com/migration'
  );
  
  // Emit telemetry
  trackDeprecatedApiUsage('x3dhInitiatorV1');
  
  // Continue with v1 implementation
  return x3dhInitiatorV1Internal(args);
}
```

**Activities**:
- Console warnings for v1 protocol usage
- Server API may return deprecation headers
- Documentation updated to recommend migration
- Provide migration tools/scripts

**Server-side deprecation headers**:
```typescript
// Server response
{
  "status": "success",
  "data": { /* ... */ },
  "warnings": [
    {
      "code": "PROTOCOL_V1_DEPRECATED",
      "message": "Protocol v1 will be sunset on 2027-06-01. Please upgrade to v2.",
      "docs_url": "https://docs.example.com/v2-migration"
    }
  ]
}
```

### Phase 3: v1 Sunset (Month 18+)

**v3.0.0 Release**:
```typescript
// v1 APIs removed
// Only v2 APIs available

// Attempting to decrypt v1 messages throws error
function ratchetDecrypt(args: any) {
  if (args.header.v === 1) {
    throw new Error(
      'Protocol v1 is no longer supported. ' +
      'Please ensure all peers have upgraded to v2. ' +
      'For migration assistance, see: https://docs.example.com/v2-migration'
    );
  }
  
  // Proceed with v2 decryption
  return ratchetDecryptV2(args);
}
```

**Activities**:
- Clients must upgrade or lose interoperability
- Sessions must be re-initialized
- Provide clear error messages with migration guidance
- Offer extended support for critical enterprise customers

## Stored Session Migration

### Automatic Upgrade (Not Recommended)

```typescript
// ❌ DON'T DO THIS - DANGEROUS
function unsafeUpgradeSession(v1Session: PersistedSessionV1): PersistedSessionV2 {
  // Attempting to convert state without re-keying is dangerous
  // Different KDF/DH/AAD assumptions may break security
  // Could result in key reuse or other vulnerabilities
  
  throw new Error('Automatic session upgrade is not supported');
}
```

**Why this is dangerous**:
- Different protocol versions may have different KDF parameters
- AAD encoding may have changed
- DH ratchet semantics may differ
- Risk of key reuse or state confusion

### Safe Approach: Re-Initialize

```typescript
class SessionMigrator {
  /**
   * Safely migrate session to v2 by performing fresh handshake.
   */
  async migrateToV2(
    oldSessionId: string,
    store: RatchetSessionStore,
    prekeyServer: PrekeyServer
  ): Promise<string> {
    const oldSession = await store.load(oldSessionId);
    if (!oldSession) {
      throw new Error(`Session ${oldSessionId} not found`);
    }
    
    if (oldSession.state.version !== 1) {
      throw new Error(`Session ${oldSessionId} is not v1`);
    }
    
    // 1. Send protocol upgrade notification to peer
    await this.sendUpgradeNotification(oldSessionId, {
      message: 'Upgrading to protocol v2',
      new_session_start_time: Date.now() + 5000, // 5s grace period
    });
    
    // 2. Archive old session (keep for 7 days for in-flight messages)
    await this.archiveSession(oldSessionId, 7 * 24 * 60 * 60 * 1000);
    
    // 3. Fetch peer's v2 prekey bundle
    const theirDeviceId = oldSession.metadata.their_device_id;
    const bundle = await prekeyServer.getBundle(theirDeviceId);
    
    if (bundle.v !== 2) {
      throw new Error(`Peer ${theirDeviceId} does not support protocol v2 yet`);
    }
    
    // 4. Perform fresh X3DH handshake with v2
    const { session_init, rk32 } = x3dhInitiatorV2({
      sender_device_id: oldSession.metadata.my_device_id,
      recipient_bundle: bundle,
      initiator_ik_priv32: await this.getIdentityPrivateKey(),
    });
    
    // 5. Initialize new v2 ratchet state
    const newState = ratchetInitV2({
      rk32,
      remoteDhPub32: await this.extractRemoteDhKey(bundle),
      sendingFirst: true,
    });
    
    // 6. Generate new session ID
    const newSessionId = computeSessionId(
      oldSession.metadata.my_device_id,
      theirDeviceId,
      'send',
      2 // protocol version
    );
    
    // 7. Save new session
    await store.save(newSessionId, {
      version: 0,
      state: newState,
      metadata: {
        protocol_version: 2,
        migrated_from: oldSessionId,
        created_at: Date.now(),
      },
    });
    
    console.log(`Migrated session ${oldSessionId} → ${newSessionId}`);
    return newSessionId;
  }
  
  /**
   * Send upgrade notification message.
   */
  private async sendUpgradeNotification(
    sessionId: string,
    notification: any
  ): Promise<void> {
    // Use existing v1 session to send final notification
    const session = await this.store.load(sessionId);
    const { header, ciphertext_b64 } = ratchetEncrypt({
      state: session.state,
      plaintext: new TextEncoder().encode(JSON.stringify({
        type: 'protocol_upgrade',
        ...notification,
      })),
      sender_device_id: session.metadata.my_device_id,
      recipient_device_id: session.metadata.their_device_id,
    });
    
    await this.transport.send({
      session_id: sessionId,
      header,
      ciphertext_b64,
    });
  }
  
  /**
   * Archive session with grace period.
   */
  private async archiveSession(
    sessionId: string,
    gracePeriodMs: number
  ): Promise<void> {
    const session = await this.store.load(sessionId);
    await this.archiveStore.save(sessionId, {
      ...session,
      archived_at: Date.now(),
      delete_at: Date.now() + gracePeriodMs,
      status: 'archived',
    });
    
    // Don't delete from active store yet - keep for in-flight messages
    await this.store.markArchived(sessionId);
  }
}
```

## Capability Advertisement

### Prekey Bundle Extension

```typescript
// v2 bundle includes capability information
interface X3DHPrekeyBundleV2 extends X3DHPrekeyBundleV1 {
  v: 2;
  
  // Optional: declare backward compatibility
  supported_protocols?: number[]; // e.g., [1, 2] during transition
  
  // v2-specific fields
  // (example - actual fields depend on v2 design)
  quantum_resistant_key?: string;
  enhanced_forward_secrecy?: boolean;
}
```

### Discovery Endpoint

```typescript
// Server provides capability lookup
interface DeviceCapabilities {
  device_id: string;
  protocols: number[];
  preferred_protocol: number;
  library_version: string;
  last_updated: number;
}

// GET /api/devices/{device_id}/capabilities
async function getDeviceCapabilities(deviceId: string): Promise<DeviceCapabilities> {
  const response = await fetch(`/api/devices/${deviceId}/capabilities`);
  return response.json();
}

// Example response:
{
  "device_id": "alice-001",
  "protocols": [1, 2],
  "preferred_protocol": 2,
  "library_version": "2.1.0",
  "last_updated": 1704988800000
}
```

### Capability Registration

```typescript
// Client registers capabilities on startup
async function registerCapabilities(
  deviceId: string,
  capabilities: DeviceCapabilities
): Promise<void> {
  await fetch('/api/devices/capabilities', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      device_id: deviceId,
      protocols: [1, 2], // Supports both v1 and v2
      preferred_protocol: 2,
      library_version: packageJson.version,
    }),
  });
}
```

## Breaking Changes Checklist

When introducing v2, document all breaking changes:

### Wire Format Changes
- [ ] List all modified fields in `HeaderProtoV1` → `HeaderProtoV2`
- [ ] List all modified fields in `X3DHPrekeyBundleV1` → `X3DHPrekeyBundleV2`
- [ ] Document any new required fields
- [ ] Document any removed fields

### Cryptographic Changes
- [ ] New/removed algorithms (e.g., post-quantum)
- [ ] Modified key derivation functions
- [ ] Changed nonce/IV generation
- [ ] Updated MAC/signature schemes

### Protocol Semantics
- [ ] Modified AAD encoding rules
- [ ] Altered message number semantics
- [ ] Changed DH ratchet advancement logic
- [ ] Updated replay protection mechanism

### State Schema Changes
- [ ] Modified `RatchetState` structure
- [ ] Changed session serialization format
- [ ] Updated skipped message key storage

### API Changes
- [ ] Breaking changes to public API
- [ ] Removed deprecated functions
- [ ] Modified function signatures
- [ ] Changed error handling

## Testing Strategy

### Cross-Version Compatibility Tests

```typescript
import { describe, it, expect } from 'vitest';
import { loadTestVector } from './test-vectors';

describe('Cross-version compatibility', () => {
  it('v2 client can decrypt v1 messages', () => {
    // Load v1 test vector
    const v1TestVector = loadTestVector('v1/basic-message.json');
    
    // Decrypt using v2 library
    const { plaintext } = ratchetDecrypt({
      state: v1TestVector.receiver_state,
      header: v1TestVector.header,
      ciphertext_b64: v1TestVector.ciphertext_b64,
    });
    
    expect(plaintext).toEqual(v1TestVector.expected_plaintext);
  });
  
  it('v2 client rejects v3 messages with clear error', () => {
    const v3Message = {
      v: 3,
      // ... other fields
    };
    
    expect(() => {
      ratchetDecrypt({ header: v3Message, /* ... */ });
    }).toThrow(/unsupported.*version.*3/i);
  });
  
  it('handles protocol negotiation correctly', async () => {
    const negotiator = new ProtocolNegotiator();
    
    // Both support v1 and v2
    const selected = await negotiator.selectProtocol(
      { device_id: 'alice', supported_protocols: [1, 2], preferred_protocol: 2 },
      { device_id: 'bob', supported_protocols: [1, 2], preferred_protocol: 2 }
    );
    
    expect(selected).toBe(2); // Highest common version
  });
  
  it('falls back to v1 when peer only supports v1', async () => {
    const negotiator = new ProtocolNegotiator();
    
    const selected = await negotiator.selectProtocol(
      { device_id: 'alice', supported_protocols: [1, 2], preferred_protocol: 2 },
      { device_id: 'bob', supported_protocols: [1], preferred_protocol: 1 }
    );
    
    expect(selected).toBe(1); // Fall back to v1
  });
});
```

### Test Vector Generation

```typescript
// Generate test vectors for v1 that can be used by v2
function generateV1TestVectors(): void {
  const vectors = [
    {
      name: 'basic-message',
      protocol_version: 1,
      plaintext: 'Hello, World!',
      // ... generate complete session state, encrypt, capture output
    },
    {
      name: 'out-of-order',
      protocol_version: 1,
      // ... test out-of-order message handling
    },
  ];
  
  writeFileSync('./vectors/v1-compat.json', JSON.stringify(vectors, null, 2));
}
```

## Migration Tools

### CLI Migration Tool

```typescript
#!/usr/bin/env node

import { program } from 'commander';

program
  .name('moretag-migrate')
  .description('Migrate moretag-crypto sessions to new protocol version')
  .version('1.0.0');

program
  .command('analyze')
  .description('Analyze sessions and report protocol versions')
  .action(async () => {
    const sessions = await loadAllSessions();
    const v1Count = sessions.filter(s => s.state.version === 1).length;
    const v2Count = sessions.filter(s => s.state.version === 2).length;
    
    console.log(`Total sessions: ${sessions.length}`);
    console.log(`  v1: ${v1Count} (${(v1Count / sessions.length * 100).toFixed(1)}%)`);
    console.log(`  v2: ${v2Count} (${(v2Count / sessions.length * 100).toFixed(1)}%)`);
  });

program
  .command('upgrade')
  .description('Upgrade all v1 sessions to v2')
  .option('--dry-run', 'Show what would be done without making changes')
  .action(async (options) => {
    const migrator = new SessionMigrator();
    const sessions = await loadAllSessions();
    const v1Sessions = sessions.filter(s => s.state.version === 1);
    
    console.log(`Found ${v1Sessions.length} v1 sessions to upgrade`);
    
    for (const session of v1Sessions) {
      if (options.dryRun) {
        console.log(`[DRY RUN] Would upgrade ${session.id}`);
      } else {
        try {
          const newId = await migrator.migrateToV2(session.id, store, prekeyServer);
          console.log(`✓ Upgraded ${session.id} → ${newId}`);
        } catch (err) {
          console.error(`✗ Failed to upgrade ${session.id}:`, err.message);
        }
      }
    }
  });

program.parse();
```

## See Also

- [SPEC.md](./SPEC.md) - v1 protocol freeze and stability guarantees
- [RELEASE.md](./RELEASE.md) - Release process and versioning
- [Test Vectors](../vectors/) - Cross-version test data
- [SESSION_LIFECYCLE.md](./SESSION_LIFECYCLE.md) - Session management

# Session Identifier Guidelines

## Overview

The moretag-crypto library does not generate session identifiers. Applications MUST implement their own session ID scheme based on their architecture.

Session IDs are critical for:
- Mapping encrypted messages to the correct ratchet state
- Preventing session confusion attacks
- Supporting multi-device and multi-peer scenarios
- Enabling efficient session lookup in storage systems

## Recommended Schemes

### 1. Unidirectional Sessions (Recommended)

Maintain separate sessions for each direction:

```typescript
import { sha256 } from '@noble/hashes/sha2';

function computeSessionId(
  myDeviceId: string,
  theirDeviceId: string,
  direction: 'send' | 'recv'
): string {
  const input = `${myDeviceId}||${theirDeviceId}||${direction}`;
  const hash = sha256(new TextEncoder().encode(input));
  return Array.from(hash)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

// Usage
const sendSession = computeSessionId("alice-001", "bob-001", "send");
const recvSession = computeSessionId("alice-001", "bob-001", "recv");
```

**Advantages**:
- Clear separation of send/receive state
- Easier to debug message flow
- Matches test patterns in codebase
- Simplifies concurrent message handling

**When to use**:
- Multi-device messaging apps
- High-volume bidirectional communication
- Applications requiring detailed audit logs

### 2. Bidirectional Sessions

Single session for both directions:

```typescript
function computeBidirectionalSessionId(deviceA: string, deviceB: string): string {
  // Canonicalize order to ensure both parties compute same ID
  const [first, second] = [deviceA, deviceB].sort();
  const input = `${first}||${second}`;
  const hash = sha256(new TextEncoder().encode(input));
  return Array.from(hash)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}
```

**Trade-offs**:
- Simpler: only one session to manage per peer
- Must handle state initialization carefully (who sends first?)
- Requires coordination for DH ratchet advances
- Both parties must agree on initialization order

**When to use**:
- Simple peer-to-peer applications
- Low message volume scenarios
- Constrained storage environments

### 3. UUID-Based (Simple but requires coordination)

```typescript
// Server generates on session creation
const sessionId = crypto.randomUUID();

// Or use a deterministic UUID v5 based on device IDs
import { v5 as uuidv5 } from 'uuid';

const NAMESPACE = '6ba7b810-9dad-11d1-80b4-00c04fd430c8'; // Custom namespace UUID

function computeUuidSessionId(deviceA: string, deviceB: string): string {
  const [first, second] = [deviceA, deviceB].sort();
  return uuidv5(`${first}:${second}`, NAMESPACE);
}
```

**When to use**: Centralized server assigns session IDs

**Trade-offs**:
- Requires server roundtrip for session establishment
- Simpler collision avoidance
- May not work in fully decentralized scenarios

## Anti-Patterns

### ❌ Don't: Use predictable IDs

```typescript
// BAD - predictable and enumerable
const sessionId = `${userId1}-${userId2}`;
const sessionId = `session-${counter++}`;
```

**Risk**: Vulnerable to enumeration attacks. Attackers can guess valid session IDs and attempt unauthorized access.

### ❌ Don't: Reuse session IDs after reset

```typescript
// BAD - reusing IDs after termination
async function resetSession(sessionId: string) {
  await store.delete(sessionId);
  // Don't reuse this sessionId for a new session!
  const newState = await initializeSession();
  await store.save(sessionId, newState); // WRONG
}
```

**Risk**: Key reuse vulnerabilities. Old messages could be replayed or state confusion could occur.

**Fix**: Always generate fresh session IDs:

```typescript
async function resetSession(oldSessionId: string) {
  await store.delete(oldSessionId);
  const newSessionId = generateNewSessionId(); // Fresh ID
  const newState = await initializeSession();
  await store.save(newSessionId, newState);
  return newSessionId;
}
```

### ❌ Don't: Use user identifiers alone

```typescript
// BAD - no device scoping
const sessionId = computeHash(`${aliceUserId}||${bobUserId}`);
```

**Risk**: Multi-device scenarios will collide. User Alice on phone and Alice on laptop would share the same session ID.

**Fix**: Always include device identifiers:

```typescript
const sessionId = computeHash(`${aliceDeviceId}||${bobDeviceId}`);
```

## Scoping Considerations

### Per-Device (Recommended)

Session ID includes device identifiers:

```typescript
interface DeviceIdentifier {
  userId: string;
  deviceId: string;
}

function computePerDeviceSessionId(
  myDevice: DeviceIdentifier,
  theirDevice: DeviceIdentifier,
  direction: 'send' | 'recv'
): string {
  const myId = `${myDevice.userId}:${myDevice.deviceId}`;
  const theirId = `${theirDevice.userId}:${theirDevice.deviceId}`;
  const input = `${myId}||${theirId}||${direction}`;
  return bytesToHex(sha256(new TextEncoder().encode(input)));
}
```

**Benefits**:
- User can have multiple sessions across devices
- Most secure and flexible
- Natural support for device-specific keys
- Enables per-device feature flags

**Considerations**:
- More sessions to manage per user
- Requires device registration system
- Need to handle device removal/revocation

### Per-User

Session ID based on user identifiers only:

```typescript
function computePerUserSessionId(
  myUserId: string,
  theirUserId: string
): string {
  const [first, second] = [myUserId, theirUserId].sort();
  const input = `${first}||${second}`;
  return bytesToHex(sha256(new TextEncoder().encode(input)));
}
```

**Trade-offs**:
- Requires multi-device key aggregation/synchronization
- Complex to implement correctly
- May not provide device-level forward secrecy
- Single point of compromise affects all devices

**When to use**:
- Single-device applications only
- Legacy system migrations
- Simplified user experience requirements

## Storage Mapping

### Session Metadata

Store metadata separately from ratchet state for efficient lookups:

```typescript
interface SessionMetadata {
  sessionId: string;
  myDeviceId: string;
  theirDeviceId: string;
  theirIdentityKeyB64: string; // Base64 X25519 pub
  direction: 'send' | 'recv' | 'bidirectional';
  createdAt: number;
  lastMessageAt: number;
  messageCount: number;
}

// In-memory index for fast lookups
class SessionRegistry {
  private bySessionId = new Map<string, SessionMetadata>();
  private byDevicePair = new Map<string, string[]>(); // device pair → session IDs
  
  register(meta: SessionMetadata): void {
    this.bySessionId.set(meta.sessionId, meta);
    
    const pairKey = this.makePairKey(meta.myDeviceId, meta.theirDeviceId);
    const sessions = this.byDevicePair.get(pairKey) || [];
    sessions.push(meta.sessionId);
    this.byDevicePair.set(pairKey, sessions);
  }
  
  findByDevicePair(myDeviceId: string, theirDeviceId: string): SessionMetadata[] {
    const pairKey = this.makePairKey(myDeviceId, theirDeviceId);
    const sessionIds = this.byDevicePair.get(pairKey) || [];
    return sessionIds.map(id => this.bySessionId.get(id)!).filter(Boolean);
  }
  
  private makePairKey(deviceA: string, deviceB: string): string {
    return `${deviceA}<->${deviceB}`;
  }
}
```

### Database Schema Example

For applications using SQL databases:

```sql
CREATE TABLE session_metadata (
  session_id VARCHAR(64) PRIMARY KEY,
  my_device_id VARCHAR(64) NOT NULL,
  their_device_id VARCHAR(64) NOT NULL,
  their_identity_key_b64 TEXT NOT NULL,
  direction VARCHAR(16) NOT NULL,
  created_at BIGINT NOT NULL,
  last_message_at BIGINT NOT NULL,
  message_count INTEGER DEFAULT 0,
  
  INDEX idx_device_pair (my_device_id, their_device_id),
  INDEX idx_last_message (last_message_at)
);

CREATE TABLE session_state (
  session_id VARCHAR(64) PRIMARY KEY,
  version INTEGER NOT NULL,
  state_json TEXT NOT NULL,
  updated_at BIGINT NOT NULL,
  
  FOREIGN KEY (session_id) REFERENCES session_metadata(session_id)
);
```

## Collision Prevention

### Hash-Based IDs (Recommended)

Using SHA-256 ensures negligible collision probability:

```typescript
function computeSessionId(
  myDeviceId: string,
  theirDeviceId: string,
  direction: 'send' | 'recv'
): string {
  const input = `${myDeviceId}||${theirDeviceId}||${direction}`;
  const hash = sha256(new TextEncoder().encode(input));
  
  // 256-bit hash provides ~2^128 collision resistance
  return Array.from(hash)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}
```

**Collision probability**: For SHA-256, collision probability is negligible (< 2^-128) even with billions of sessions.

### UUID v4 (Alternative)

```typescript
import { randomUUID } from 'crypto';

function generateSessionId(): string {
  return randomUUID(); // 122 bits of randomness
}
```

**Collision probability**: ~2^-61 for 1 billion UUIDs. Sufficient for most applications.

### Collision Detection

Despite low probability, implement detection:

```typescript
async function createSession(
  myDeviceId: string,
  theirDeviceId: string,
  direction: 'send' | 'recv'
): Promise<string> {
  let attempt = 0;
  const maxAttempts = 3;
  
  while (attempt < maxAttempts) {
    const sessionId = computeSessionId(myDeviceId, theirDeviceId, direction);
    
    const existing = await store.load(sessionId);
    if (!existing) {
      return sessionId; // No collision
    }
    
    // Collision detected (very rare!)
    console.warn(`Session ID collision detected: ${sessionId}`);
    
    // Add salt to ensure different ID
    const salt = randomBytes(16);
    const sessionIdWithSalt = computeSessionId(
      `${myDeviceId}:${bytesToHex(salt)}`,
      theirDeviceId,
      direction
    );
    
    attempt++;
    if (attempt < maxAttempts) continue;
    
    throw new Error('Failed to generate unique session ID after retries');
  }
  
  throw new Error('Unreachable');
}
```

## Migration Considerations

### Changing Session ID Schemes

If you need to change your session ID scheme:

```typescript
async function migrateSessionIds(
  oldScheme: (a: string, b: string) => string,
  newScheme: (a: string, b: string) => string
): Promise<void> {
  const allSessions = await store.listAll();
  
  for (const session of allSessions) {
    const meta = await getSessionMetadata(session.id);
    
    // Compute new ID
    const newId = newScheme(meta.myDeviceId, meta.theirDeviceId);
    
    // Check if new ID already exists
    if (await store.exists(newId)) {
      console.warn(`Migration conflict for session ${session.id}`);
      continue; // Skip or handle specially
    }
    
    // Copy to new ID
    await store.save(newId, session.state);
    await updateMetadata(newId, meta);
    
    // Keep old ID active for grace period
    await markForDeletion(session.id, Date.now() + 7 * 24 * 60 * 60 * 1000);
  }
}
```

## Helper Utilities

### Complete Session ID Implementation

```typescript
import { sha256 } from '@noble/hashes/sha2';

export class SessionIdGenerator {
  /**
   * Generate a deterministic session ID for unidirectional sessions.
   * Both parties must agree on direction convention.
   */
  static unidirectional(
    myDeviceId: string,
    theirDeviceId: string,
    direction: 'send' | 'recv'
  ): string {
    if (!myDeviceId || !theirDeviceId) {
      throw new TypeError('Device IDs must be non-empty');
    }
    if (direction !== 'send' && direction !== 'recv') {
      throw new TypeError('Direction must be "send" or "recv"');
    }
    
    const input = `${myDeviceId}||${theirDeviceId}||${direction}`;
    const hash = sha256(new TextEncoder().encode(input));
    return Array.from(hash)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }
  
  /**
   * Generate a deterministic session ID for bidirectional sessions.
   * Order-independent: both parties compute the same ID.
   */
  static bidirectional(deviceA: string, deviceB: string): string {
    if (!deviceA || !deviceB) {
      throw new TypeError('Device IDs must be non-empty');
    }
    
    const [first, second] = [deviceA, deviceB].sort();
    const input = `${first}||${second}`;
    const hash = sha256(new TextEncoder().encode(input));
    return Array.from(hash)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }
  
  /**
   * Generate a random session ID (server-assigned scenarios).
   */
  static random(): string {
    return randomUUID();
  }
}
```

## Testing Session ID Generation

```typescript
import { describe, it, expect } from 'vitest';
import { SessionIdGenerator } from './session-id';

describe('SessionIdGenerator', () => {
  it('generates deterministic unidirectional IDs', () => {
    const id1 = SessionIdGenerator.unidirectional('alice-001', 'bob-001', 'send');
    const id2 = SessionIdGenerator.unidirectional('alice-001', 'bob-001', 'send');
    expect(id1).toBe(id2);
    expect(id1).toHaveLength(64); // SHA-256 hex
  });
  
  it('generates different IDs for different directions', () => {
    const sendId = SessionIdGenerator.unidirectional('alice-001', 'bob-001', 'send');
    const recvId = SessionIdGenerator.unidirectional('alice-001', 'bob-001', 'recv');
    expect(sendId).not.toBe(recvId);
  });
  
  it('generates order-independent bidirectional IDs', () => {
    const id1 = SessionIdGenerator.bidirectional('alice-001', 'bob-001');
    const id2 = SessionIdGenerator.bidirectional('bob-001', 'alice-001');
    expect(id1).toBe(id2);
  });
  
  it('generates unique random IDs', () => {
    const id1 = SessionIdGenerator.random();
    const id2 = SessionIdGenerator.random();
    expect(id1).not.toBe(id2);
    expect(id1).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
  });
});
```

## See Also

- [src/integration.test.ts](../src/integration.test.ts) - Example implementation with `computeSessionId` helper
- [docs/SPEC.md](./SPEC.md) - Wire format stability guarantees
- [docs/SESSION_LIFECYCLE.md](./SESSION_LIFECYCLE.md) - Session expiry and rekey policies
- [docs/THREAT_MODEL.md](./THREAT_MODEL.md) - Security assumptions

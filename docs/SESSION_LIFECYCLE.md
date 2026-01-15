# Session Lifecycle Management

## Overview

While the Double Ratchet provides forward secrecy through continuous re-keying, sessions should have bounded lifetimes for operational and security reasons. Unbounded sessions can lead to:

- **Key exhaustion**: Risk of key reuse after reaching implementation limits
- **State bloat**: Skipped message keys accumulate over time
- **Operational complexity**: Debugging stale sessions is difficult
- **Security hygiene**: Regular re-keying limits exposure from key compromise

This guide defines session lifecycle policies for production deployments.

## Recommended Limits

### Session Age

**Recommended**: 30-90 days maximum

```typescript
const SESSION_MAX_AGE_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

interface SessionMetadata {
  sessionId: string;
  createdAt: number;
  lastMessageAt: number;
  myDeviceId: string;
  theirDeviceId: string;
}

function isSessionExpired(meta: SessionMetadata): boolean {
  const age = Date.now() - meta.createdAt;
  return age > SESSION_MAX_AGE_MS;
}

function getSessionAge(meta: SessionMetadata): number {
  return Date.now() - meta.createdAt;
}

function getSessionAgeDays(meta: SessionMetadata): number {
  return Math.floor(getSessionAge(meta) / (24 * 60 * 60 * 1000));
}
```

**Why limit session age?**
- Limits impact of key compromise (forward secrecy boundary)
- Forces periodic re-initialization with fresh keys
- Aligns with key rotation policies
- Prevents accumulation of skipped message keys

**Choosing age limit**:
- **High security**: 7-14 days
- **Standard**: 30 days
- **Low frequency messaging**: 90 days

### Message Count

**Recommended**: 10,000-50,000 messages per session

```typescript
const SESSION_MAX_MESSAGES = 10_000;

interface SessionState extends RatchetState {
  totalMessagesSent: number;
  totalMessagesReceived: number;
}

function shouldRekeyByMessageCount(state: SessionState): boolean {
  const total = state.totalMessagesSent + state.totalMessagesReceived;
  return total >= SESSION_MAX_MESSAGES;
}

function getMessageCount(state: SessionState): number {
  return state.totalMessagesSent + state.totalMessagesReceived;
}

function getRemainingMessages(state: SessionState): number {
  return SESSION_MAX_MESSAGES - getMessageCount(state);
}
```

**Why limit message count?**
- Protects against message number overflow
- Limits skipped message key storage growth
- Reduces risk from long-lived chain keys
- Provides predictable re-key triggers

**Implementation note**: Track message counts separately from ratchet state since `RatchetState` only maintains internal counters.

### Inactivity Timeout

**Recommended**: 7-14 days of inactivity

```typescript
const SESSION_INACTIVITY_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

function isSessionInactive(meta: SessionMetadata): boolean {
  const idle = Date.now() - meta.lastMessageAt;
  return idle > SESSION_INACTIVITY_MS;
}

function getIdleDays(meta: SessionMetadata): number {
  const idle = Date.now() - meta.lastMessageAt;
  return Math.floor(idle / (24 * 60 * 60 * 1000));
}

function updateLastMessageTime(sessionId: string): void {
  const meta = getMetadata(sessionId);
  meta.lastMessageAt = Date.now();
  saveMetadata(sessionId, meta);
}
```

**Why timeout inactive sessions?**
- Free up storage resources
- Reduce attack surface (fewer sessions to protect)
- Indicate stale peer relationships
- Trigger re-authentication for returning users

## Termination Triggers

Automatically re-initialize sessions when:

### 1. Age Limit Reached
```typescript
if (getSessionAgeDays(meta) >= 30) {
  await terminateSession(sessionId, 'age_limit_exceeded');
}
```

### 2. Message Count Exceeded
```typescript
if (getMessageCount(state) >= SESSION_MAX_MESSAGES) {
  await terminateSession(sessionId, 'message_count_exceeded');
}
```

### 3. Prolonged Inactivity
```typescript
if (getIdleDays(meta) >= 7) {
  await terminateSession(sessionId, 'inactivity_timeout');
}
```

### 4. Peer Identity Key Rotated
```typescript
// Server notifies client of identity key change
async function handleIdentityKeyRotation(deviceId: string): Promise<void> {
  const sessions = await findSessionsWithPeer(deviceId);
  
  for (const sessionId of sessions) {
    await terminateSession(sessionId, 'peer_identity_rotated');
  }
}
```

### 5. Security Event
```typescript
// Emergency rotation in response to vulnerability
async function handleSecurityEvent(eventType: string): Promise<void> {
  const allSessions = await listAllSessions();
  
  for (const sessionId of allSessions) {
    await terminateSession(sessionId, `security_event:${eventType}`);
  }
  
  console.log(`Terminated ${allSessions.length} sessions due to security event`);
}
```

## Session Health Monitoring

```typescript
type SessionHealth = 'healthy' | 'warning' | 'critical';

interface SessionHealthReport {
  sessionId: string;
  health: SessionHealth;
  age_ms: number;
  message_count: number;
  idle_ms: number;
  issues: string[];
}

class SessionHealthChecker {
  /**
   * Assess session health based on all limits.
   */
  async checkSessionHealth(sessionId: string): Promise<SessionHealthReport> {
    const meta = await getMetadata(sessionId);
    const session = await store.load(sessionId);
    
    if (!session) {
      return {
        sessionId,
        health: 'critical',
        age_ms: 0,
        message_count: 0,
        idle_ms: 0,
        issues: ['session_not_found'],
      };
    }
    
    const age = getSessionAge(meta);
    const messageCount = getMessageCount(session.state);
    const idle = Date.now() - meta.lastMessageAt;
    
    const issues: string[] = [];
    let health: SessionHealth = 'healthy';
    
    // Check age
    if (age > SESSION_MAX_AGE_MS) {
      issues.push('age_limit_exceeded');
      health = 'critical';
    } else if (age > SESSION_MAX_AGE_MS * 0.9) {
      issues.push('approaching_age_limit');
      health = 'warning';
    }
    
    // Check message count
    if (messageCount >= SESSION_MAX_MESSAGES) {
      issues.push('message_count_exceeded');
      health = 'critical';
    } else if (messageCount >= SESSION_MAX_MESSAGES * 0.9) {
      issues.push('approaching_message_limit');
      health = 'warning';
    }
    
    // Check inactivity
    if (idle > SESSION_INACTIVITY_MS) {
      issues.push('inactivity_timeout');
      health = 'critical';
    } else if (idle > SESSION_INACTIVITY_MS * 0.8) {
      issues.push('idle_warning');
      if (health === 'healthy') health = 'warning';
    }
    
    return {
      sessionId,
      health,
      age_ms: age,
      message_count: messageCount,
      idle_ms: idle,
      issues,
    };
  }
  
  /**
   * Check all sessions and return summary.
   */
  async checkAllSessions(): Promise<{
    total: number;
    healthy: number;
    warning: number;
    critical: number;
    reports: SessionHealthReport[];
  }> {
    const allSessions = await listAllSessions();
    const reports: SessionHealthReport[] = [];
    
    for (const sessionId of allSessions) {
      const report = await this.checkSessionHealth(sessionId);
      reports.push(report);
    }
    
    return {
      total: reports.length,
      healthy: reports.filter(r => r.health === 'healthy').length,
      warning: reports.filter(r => r.health === 'warning').length,
      critical: reports.filter(r => r.health === 'critical').length,
      reports,
    };
  }
}
```

## Session Manager

```typescript
class SessionManager {
  private store: FileRatchetStore;
  private healthChecker: SessionHealthChecker;
  
  constructor(store: FileRatchetStore) {
    this.store = store;
    this.healthChecker = new SessionHealthChecker();
  }
  
  /**
   * Check if session needs re-keying.
   */
  async shouldRekey(sessionId: string): Promise<{
    shouldRekey: boolean;
    reason?: string;
  }> {
    const report = await this.healthChecker.checkSessionHealth(sessionId);
    
    if (report.health === 'critical') {
      return {
        shouldRekey: true,
        reason: report.issues[0],
      };
    }
    
    return { shouldRekey: false };
  }
  
  /**
   * Re-key session if needed.
   */
  async rekeyIfNeeded(sessionId: string): Promise<string | undefined> {
    const { shouldRekey, reason } = await this.shouldRekey(sessionId);
    
    if (shouldRekey) {
      console.log(`Re-keying session ${sessionId}: ${reason}`);
      const newSessionId = await this.reinitializeSession(sessionId);
      await this.archiveOldSession(sessionId, reason);
      return newSessionId;
    }
    
    return undefined; // No rekey needed
  }
  
  /**
   * Re-initialize session with fresh X3DH handshake.
   */
  private async reinitializeSession(oldSessionId: string): Promise<string> {
    const oldMeta = await getMetadata(oldSessionId);
    
    // Fetch peer's current prekey bundle
    const bundle = await prekeyServer.getBundle(oldMeta.theirDeviceId);
    
    // Perform fresh X3DH
    const { session_init, rk32 } = x3dhInitiatorV1({
      sender_device_id: oldMeta.myDeviceId,
      recipient_bundle: bundle,
      initiator_ik_priv32: await loadIdentityPrivateKey(),
    });
    
    // Initialize new ratchet state
    const newState = ratchetInit({
      rk32,
      remoteDhPub32: base64ToBytes(bundle.spk_pub_b64),
      sendingFirst: true,
    });
    
    // Generate new session ID
    const newSessionId = computeSessionId(
      oldMeta.myDeviceId,
      oldMeta.theirDeviceId,
      'send'
    );
    
    // Save new session
    await this.store.save(newSessionId, {
      version: 0,
      state: newState,
    });
    
    // Save metadata
    await saveMetadata(newSessionId, {
      sessionId: newSessionId,
      createdAt: Date.now(),
      lastMessageAt: Date.now(),
      myDeviceId: oldMeta.myDeviceId,
      theirDeviceId: oldMeta.theirDeviceId,
    });
    
    return newSessionId;
  }
  
  /**
   * Archive old session for grace period.
   */
  private async archiveOldSession(
    sessionId: string,
    reason: string
  ): Promise<void> {
    await archiveSession(sessionId, {
      reason,
      archived_at: Date.now(),
      delete_at: Date.now() + 7 * 24 * 60 * 60 * 1000, // 7 days
    });
  }
}
```

## Graceful Session Termination

### Notify Peer Before Deletion

```typescript
interface SessionTerminationNotification {
  type: 'session_terminated';
  reason: string;
  timestamp: number;
  new_session_available: boolean;
}

async function terminateSession(
  sessionId: string,
  reason: string
): Promise<void> {
  console.log(`Terminating session ${sessionId}: ${reason}`);
  
  // 1. Send termination message to peer
  try {
    const notification: SessionTerminationNotification = {
      type: 'session_terminated',
      reason,
      timestamp: Date.now(),
      new_session_available: true,
    };
    
    await sendMessage(sessionId, JSON.stringify(notification));
  } catch (err) {
    console.warn('Failed to send termination notification:', err);
    // Continue with termination anyway
  }
  
  // 2. Wait brief period for delivery
  await sleep(5000);
  
  // 3. Archive session (don't delete immediately)
  await archiveSession(sessionId, {
    reason,
    archived_at: Date.now(),
    delete_at: Date.now() + 7 * 24 * 60 * 60 * 1000, // 7 days grace
  });
  
  console.log(`Session ${sessionId} archived (will delete after grace period)`);
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}
```

## Cleanup Procedures

### Archive Before Delete

```typescript
interface ArchivedSession {
  sessionId: string;
  archivedAt: number;
  deleteAt: number;
  reason: string;
  state: PersistedSession; // Keep for grace period
  metadata: SessionMetadata;
}

class SessionArchive {
  private archived = new Map<string, ArchivedSession>();
  
  /**
   * Archive session with grace period before permanent deletion.
   */
  archive(
    sessionId: string,
    reason: string,
    gracePeriodMs: number = 7 * 24 * 60 * 60 * 1000
  ): void {
    const session = store.load(sessionId);
    const metadata = getMetadata(sessionId);
    
    if (!session) {
      console.warn(`Cannot archive non-existent session ${sessionId}`);
      return;
    }
    
    this.archived.set(sessionId, {
      sessionId,
      archivedAt: Date.now(),
      deleteAt: Date.now() + gracePeriodMs,
      reason,
      state: session,
      metadata,
    });
    
    console.log(`Archived session ${sessionId} (delete at ${new Date(Date.now() + gracePeriodMs).toISOString()})`);
  }
  
  /**
   * Restore archived session (within grace period).
   */
  restore(sessionId: string): boolean {
    const archived = this.archived.get(sessionId);
    
    if (!archived) {
      console.warn(`No archived session found: ${sessionId}`);
      return false;
    }
    
    if (Date.now() > archived.deleteAt) {
      console.warn(`Session ${sessionId} past grace period, cannot restore`);
      return false;
    }
    
    // Restore to active store
    store.save(sessionId, archived.state);
    saveMetadata(sessionId, archived.metadata);
    
    // Remove from archive
    this.archived.delete(sessionId);
    
    console.log(`Restored session ${sessionId}`);
    return true;
  }
  
  /**
   * Process cleanup for expired archived sessions.
   */
  async processCleanup(): Promise<number> {
    const now = Date.now();
    let deletedCount = 0;
    
    for (const [id, archived] of this.archived) {
      if (archived.deleteAt < now) {
        // Permanently delete
        await this.secureDelete(id);
        this.archived.delete(id);
        deletedCount++;
        
        console.log(`Permanently deleted session ${id} (archived ${Math.floor((now - archived.archivedAt) / (24 * 60 * 60 * 1000))} days ago)`);
      }
    }
    
    return deletedCount;
  }
  
  /**
   * Securely delete session data.
   */
  private async secureDelete(sessionId: string): Promise<void> {
    // Remove from main store
    await store.delete(sessionId);
    
    // Remove metadata
    await deleteMetadata(sessionId);
    
    // Overwrite file if using file-based storage
    // (Note: actual secure deletion depends on filesystem)
  }
  
  /**
   * List all archived sessions.
   */
  listArchived(): ArchivedSession[] {
    return Array.from(this.archived.values());
  }
}
```

### Periodic Maintenance

```typescript
class SessionMaintenance {
  private interval = 24 * 60 * 60 * 1000; // Daily
  private intervalId?: NodeJS.Timeout;
  
  start(manager: SessionManager, archive: SessionArchive): void {
    console.log('Starting session maintenance service');
    
    this.intervalId = setInterval(async () => {
      try {
        await this.performMaintenance(manager, archive);
      } catch (err) {
        console.error('Maintenance failed:', err);
      }
    }, this.interval);
  }
  
  stop(): void {
    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = undefined;
      console.log('Session maintenance service stopped');
    }
  }
  
  private async performMaintenance(
    manager: SessionManager,
    archive: SessionArchive
  ): Promise<void> {
    console.log('Starting session maintenance');
    
    // 1. Check health of all active sessions
    const allSessions = await manager.listSessions();
    let archivedCount = 0;
    
    for (const sessionId of allSessions) {
      const { shouldRekey, reason } = await manager.shouldRekey(sessionId);
      
      if (shouldRekey) {
        await terminateSession(sessionId, reason);
        archivedCount++;
      }
    }
    
    console.log(`Archived ${archivedCount} sessions`);
    
    // 2. Clean up expired archived sessions
    const deletedCount = await archive.processCleanup();
    console.log(`Deleted ${deletedCount} expired archived sessions`);
    
    // 3. Generate health report
    const healthChecker = new SessionHealthChecker();
    const summary = await healthChecker.checkAllSessions();
    console.log('Session health summary:', {
      total: summary.total,
      healthy: summary.healthy,
      warning: summary.warning,
      critical: summary.critical,
    });
  }
}
```

## Monitoring Metrics

```typescript
interface SessionMetrics {
  total_active: number;
  total_archived: number;
  avg_age_ms: number;
  avg_message_count: number;
  avg_idle_ms: number;
  expiring_soon: number; // Count of sessions near limits
  health_distribution: {
    healthy: number;
    warning: number;
    critical: number;
  };
}

async function collectSessionMetrics(): Promise<SessionMetrics> {
  const sessions = await getAllSessions();
  const archived = await getArchivedSessions();
  
  const healthChecker = new SessionHealthChecker();
  const healthReports = await Promise.all(
    sessions.map(s => healthChecker.checkSessionHealth(s.sessionId))
  );
  
  return {
    total_active: sessions.length,
    total_archived: archived.length,
    avg_age_ms: average(sessions.map(s => getSessionAge(s.metadata))),
    avg_message_count: average(sessions.map(s => getMessageCount(s.state))),
    avg_idle_ms: average(sessions.map(s => Date.now() - s.metadata.lastMessageAt)),
    expiring_soon: healthReports.filter(r => r.health === 'warning').length,
    health_distribution: {
      healthy: healthReports.filter(r => r.health === 'healthy').length,
      warning: healthReports.filter(r => r.health === 'warning').length,
      critical: healthReports.filter(r => r.health === 'critical').length,
    },
  };
}

function average(numbers: number[]): number {
  if (numbers.length === 0) return 0;
  return numbers.reduce((sum, n) => sum + n, 0) / numbers.length;
}

function willExpireSoon(session: SessionMetadata): boolean {
  const age = getSessionAge(session);
  const threshold = SESSION_MAX_AGE_MS * 0.9; // 90% of limit
  return age > threshold;
}
```

## Emergency Rotation

```typescript
async function emergencyRotateAll(
  reason: string,
  notifyPeers: boolean = true
): Promise<void> {
  console.log(`EMERGENCY ROTATION: ${reason}`);
  
  const allSessions = await listAllSessions();
  console.log(`Rotating ${allSessions.length} sessions`);
  
  let successCount = 0;
  let failCount = 0;
  
  for (const sessionId of allSessions) {
    try {
      if (notifyPeers) {
        await sendSecurityAlert(sessionId, reason);
      }
      
      await terminateSession(sessionId, `security_rotation:${reason}`);
      successCount++;
    } catch (err) {
      console.error(`Failed to rotate session ${sessionId}:`, err);
      failCount++;
    }
  }
  
  console.log(`Emergency rotation complete: ${successCount} success, ${failCount} failed`);
  
  // Broadcast force re-key message to all peers
  if (notifyPeers) {
    await broadcastForceRekeyMessage(reason);
  }
}

async function sendSecurityAlert(
  sessionId: string,
  reason: string
): Promise<void> {
  const alert = {
    type: 'security_alert',
    severity: 'critical',
    reason,
    action_required: 'rekey_immediately',
    timestamp: Date.now(),
  };
  
  try {
    await sendMessage(sessionId, JSON.stringify(alert));
  } catch (err) {
    console.warn(`Failed to send security alert for ${sessionId}:`, err);
  }
}

async function broadcastForceRekeyMessage(reason: string): Promise<void> {
  // Implementation depends on your application architecture
  // Could use push notifications, WebSocket broadcast, etc.
  console.log(`Broadcasting force rekey: ${reason}`);
}
```

## Best Practices

### DO ✅

1. **Track metadata separately** from session state
   - Store creation time, last message time, message count in separate metadata store
   - Enables health checks without loading full session state

2. **Log session lifecycle events** for audit
   ```typescript
   function logSessionEvent(event: string, sessionId: string, details: any): void {
     console.log(JSON.stringify({
       timestamp: Date.now(),
       event,
       session_id: sessionId,
       ...details,
     }));
   }
   ```

3. **Implement grace periods** before deletion
   - Keep archived sessions for 7+ days
   - Allows recovery if termination was premature
   - Enables decryption of in-flight messages

4. **Monitor session health metrics**
   - Collect metrics daily
   - Alert on abnormal patterns
   - Track termination reasons for insights

5. **Test rekey flows** regularly
   - Include in integration tests
   - Simulate all termination triggers
   - Verify peer notification delivery

### DON'T ❌

1. **Don't delete immediately** on termination
   - Always use grace period
   - In-flight messages may still arrive

2. **Don't reuse session IDs** after deletion
   - Use fresh IDs for re-initialized sessions
   - Prevents confusion and potential security issues

3. **Don't ignore health warnings**
   - Address "warning" state before becoming "critical"
   - Proactive re-keying is better than forced termination

4. **Don't set arbitrary limits**
   - Base limits on actual threat model
   - Consider message frequency patterns
   - Adjust based on operational experience

5. **Don't forget peer notification**
   - Always attempt to notify peer before termination
   - Include reason and new session availability info

## Testing

```typescript
import { describe, it, expect, beforeEach } from 'vitest';

describe('Session Lifecycle', () => {
  let manager: SessionManager;
  let archive: SessionArchive;
  
  beforeEach(() => {
    manager = new SessionManager(new FileRatchetStore('/tmp/test'));
    archive = new SessionArchive();
  });
  
  it('detects expired sessions by age', async () => {
    const sessionId = 'test-session-1';
    const meta: SessionMetadata = {
      sessionId,
      createdAt: Date.now() - 31 * 24 * 60 * 60 * 1000, // 31 days ago
      lastMessageAt: Date.now(),
      myDeviceId: 'alice',
      theirDeviceId: 'bob',
    };
    
    expect(isSessionExpired(meta)).toBe(true);
  });
  
  it('detects inactive sessions', async () => {
    const meta: SessionMetadata = {
      sessionId: 'test-session-2',
      createdAt: Date.now(),
      lastMessageAt: Date.now() - 8 * 24 * 60 * 60 * 1000, // 8 days ago
      myDeviceId: 'alice',
      theirDeviceId: 'bob',
    };
    
    expect(isSessionInactive(meta)).toBe(true);
  });
  
  it('archives session with grace period', () => {
    const sessionId = 'test-session-3';
    archive.archive(sessionId, 'test', 7 * 24 * 60 * 60 * 1000);
    
    const archived = archive.listArchived();
    expect(archived).toHaveLength(1);
    expect(archived[0].sessionId).toBe(sessionId);
  });
  
  it('can restore archived session within grace period', () => {
    const sessionId = 'test-session-4';
    archive.archive(sessionId, 'test', 7 * 24 * 60 * 60 * 1000);
    
    const restored = archive.restore(sessionId);
    expect(restored).toBe(true);
    expect(archive.listArchived()).toHaveLength(0);
  });
  
  it('deletes expired archived sessions', async () => {
    const sessionId = 'test-session-5';
    archive.archive(sessionId, 'test', -1000); // Already expired
    
    const deletedCount = await archive.processCleanup();
    expect(deletedCount).toBe(1);
    expect(archive.listArchived()).toHaveLength(0);
  });
});
```

## Production Checklist

Before deploying session lifecycle management:

- [ ] Set session age limit (30-90 days)
- [ ] Set message count limit (10k-50k)
- [ ] Set inactivity timeout (7-14 days)
- [ ] Implement health checking
- [ ] Implement automated maintenance
- [ ] Configure archive grace period (7+ days)
- [ ] Set up monitoring and alerting
- [ ] Test peer notification delivery
- [ ] Test session restoration from archive
- [ ] Document operational procedures
- [ ] Plan emergency rotation process

## See Also

- [SESSION_ID_GUIDELINES.md](./SESSION_ID_GUIDELINES.md) - Session identifier generation
- [PREKEY_ROTATION.md](./PREKEY_ROTATION.md) - Prekey management and rotation
- [THREAT_MODEL.md](./THREAT_MODEL.md) - Security assumptions
- [IDENTITY_PERSISTENCE.md](./IDENTITY_PERSISTENCE.md) - Identity key rotation
- [src/integration.test.ts](../src/integration.test.ts) - Complete end-to-end example

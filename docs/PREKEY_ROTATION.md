# Prekey Rotation Policy

## Overview

Proper prekey management is critical for forward secrecy and availability. Stale or exhausted prekeys can result in:
- **Failed session establishment** if OPKs are depleted
- **Reduced forward secrecy** with overused SPKs
- **Key compromise risk** from long-lived keys
- **Operational issues** from insufficient monitoring

This guide provides concrete policies and automation strategies for production deployments.

## Signed Prekey (SPK) Rotation

### Rotation Frequency

**Recommended**: Every 7-30 days

```typescript
import { X3DHPrekeyManagerV1 } from 'moretag-crypto';

const SPK_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

class PrekeyRotationManager {
  private manager: X3DHPrekeyManagerV1;
  private lastSpkRotation: number;
  
  constructor(manager: X3DHPrekeyManagerV1) {
    this.manager = manager;
    this.lastSpkRotation = Date.now();
  }
  
  shouldRotateSpk(): boolean {
    return Date.now() - this.lastSpkRotation > SPK_MAX_AGE_MS;
  }
  
  async rotateSpkIfNeeded(): Promise<boolean> {
    if (this.shouldRotateSpk()) {
      const newSpkId = Date.now();
      this.manager.rotateSignedPrekey(newSpkId);
      this.lastSpkRotation = Date.now();
      
      // Publish new bundle to server
      await this.publishBundle();
      
      console.log(`SPK rotated: ${newSpkId}`);
      return true;
    }
    return false;
  }
  
  private async publishBundle(): Promise<void> {
    const bundle = this.manager.getPrekeyBundle();
    // Implementation depends on your server API
    await fetch('/api/prekeys', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(bundle),
    });
  }
}
```

### Rotation Triggers

Rotate SPK when:
1. **Age threshold exceeded** (7-30 days)
2. **Compromise suspected** (immediate rotation)
3. **Cryptographic vulnerability** discovered
4. **Compliance requirements** (e.g., yearly rotation policy)

### Overlap Period

Keep old SPK valid for 24-48 hours after rotation to handle in-flight session initializations:

```typescript
interface SignedPrekeyWithExpiry {
  spk_id: string | number;
  spk_pub_b64: string;
  spk_sig_b64: string;
  ik_sig_pub_b64: string;
  created_at: number;
  expires_at: number;
  status: 'active' | 'retiring' | 'expired';
}

class PrekeyStore {
  private spks = new Map<string | number, SignedPrekeyWithExpiry>();
  
  /**
   * Add new SPK with expiration timestamp.
   */
  addSpk(record: SignedPrekeyRecord, maxAgeMs: number): void {
    // Mark current active SPK as retiring
    for (const [id, spk] of this.spks) {
      if (spk.status === 'active') {
        spk.status = 'retiring';
        spk.expires_at = Date.now() + 48 * 60 * 60 * 1000; // 48h overlap
      }
    }
    
    // Add new active SPK
    this.spks.set(record.spk_id, {
      ...record,
      created_at: Date.now(),
      expires_at: Date.now() + maxAgeMs,
      status: 'active',
    });
  }
  
  /**
   * Get SPK by ID (for responder looking up initiator's SPK reference).
   */
  getSpk(spkId: string | number): SignedPrekeyWithExpiry | undefined {
    const spk = this.spks.get(spkId);
    if (!spk) return undefined;
    if (spk.status === 'expired') return undefined;
    return spk;
  }
  
  /**
   * Get current active SPK.
   */
  getActiveSpk(): SignedPrekeyWithExpiry | undefined {
    for (const spk of this.spks.values()) {
      if (spk.status === 'active') return spk;
    }
    return undefined;
  }
  
  /**
   * Remove expired SPKs.
   */
  pruneExpired(): void {
    const now = Date.now();
    for (const [id, spk] of this.spks) {
      if (spk.status === 'retiring' && spk.expires_at < now) {
        spk.status = 'expired';
        console.log(`SPK ${id} expired`);
      }
      
      // Delete expired SPKs after safety buffer
      if (spk.status === 'expired' && spk.expires_at + 7 * 24 * 60 * 60 * 1000 < now) {
        this.spks.delete(id);
        console.log(`SPK ${id} deleted`);
      }
    }
  }
}
```

## One-Time Prekeys (OPK)

### Initial Pool Size

**Recommended**: 100-200 OPKs per device

```typescript
async function initializeDevice(deviceId: string): Promise<X3DHPrekeyManagerV1> {
  const manager = new X3DHPrekeyManagerV1({ recipient_device_id: deviceId });
  
  // Generate initial SPK
  manager.rotateSignedPrekey(Date.now());
  
  // Generate initial OPK pool
  const opks = manager.addOneTimePrekeys({ startId: 1, count: 100 });
  
  // Publish to server
  await publishPrekeyBundle(manager.getPrekeyBundle());
  
  console.log(`Device ${deviceId} initialized with 100 OPKs`);
  return manager;
}
```

**Pool size considerations**:
- **Small apps** (< 100 active users): 50-100 OPKs
- **Medium apps** (100-10K users): 100-200 OPKs
- **Large apps** (> 10K users): 200-500 OPKs
- **High-frequency messaging**: Increase by 2-3x

### Refill Triggers

Refill when OPK count drops below threshold:

```typescript
const OPK_LOW_THRESHOLD = 20;
const OPK_REFILL_COUNT = 50;

interface PrekeyServer {
  getOpkCount(deviceId: string): Promise<number>;
  getNextOpkId(deviceId: string): Promise<number>;
  publishOpks(deviceId: string, opks: OneTimePrekeyRecord[]): Promise<void>;
}

async function checkAndRefillOpks(
  manager: X3DHPrekeyManagerV1,
  server: PrekeyServer
): Promise<void> {
  const currentCount = await server.getOpkCount(manager.recipient_device_id);
  
  if (currentCount < OPK_LOW_THRESHOLD) {
    console.warn(`OPK count low: ${currentCount}/${OPK_LOW_THRESHOLD}`);
    
    const nextId = await server.getNextOpkId(manager.recipient_device_id);
    const newOpks = manager.addOneTimePrekeys({
      startId: nextId,
      count: OPK_REFILL_COUNT,
    });
    
    await server.publishOpks(manager.recipient_device_id, newOpks);
    
    console.log(`Refilled ${OPK_REFILL_COUNT} OPKs (now ${currentCount + OPK_REFILL_COUNT})`);
  }
}
```

### Refill Strategy Options

**1. Threshold-Based (Recommended)**
```typescript
// Trigger refill when count drops below threshold
if (currentCount < 20) {
  refill(50);
}
```
**Pros**: Simple, prevents exhaustion  
**Cons**: May cause refill storms if many devices hit threshold simultaneously

**2. Percentage-Based**
```typescript
// Trigger when 80% consumed
const initialSize = 100;
if (currentCount < initialSize * 0.2) {
  refill(50);
}
```
**Pros**: Scales with pool size  
**Cons**: Requires tracking initial size

**3. Rate-Based**
```typescript
// Refill based on consumption rate
const consumptionRate = getOpkConsumptionRate(7); // last 7 days
const daysRemaining = currentCount / (consumptionRate || 1);

if (daysRemaining < 2) {
  const neededForWeek = Math.ceil(consumptionRate * 7);
  refill(neededForWeek);
}
```
**Pros**: Adaptive to usage patterns  
**Cons**: More complex, requires historical data

### OPK Expiry

**Recommended**: 90 days maximum age

```typescript
// Server-side logic
interface StoredOpk {
  opk_id: string | number;
  device_id: string;
  opk_pub_b64: string;
  uploaded_at: number;
  consumed_at?: number;
}

class OpkStore {
  private opks = new Map<string, StoredOpk>();
  
  /**
   * Prune OPKs older than max age.
   */
  pruneExpiredOpks(deviceId: string): void {
    const MAX_OPK_AGE = 90 * 24 * 60 * 60 * 1000; // 90 days
    const cutoff = Date.now() - MAX_OPK_AGE;
    
    let deletedCount = 0;
    for (const [id, opk] of this.opks) {
      if (opk.device_id === deviceId && opk.uploaded_at < cutoff) {
        this.opks.delete(id);
        deletedCount++;
      }
    }
    
    if (deletedCount > 0) {
      console.log(`Pruned ${deletedCount} expired OPKs for ${deviceId}`);
    }
  }
  
  /**
   * Get and consume OPK (mark as used).
   */
  consumeOpk(deviceId: string): StoredOpk | undefined {
    // Find oldest unused OPK for fairness
    let oldest: StoredOpk | undefined;
    let oldestId: string | undefined;
    
    for (const [id, opk] of this.opks) {
      if (opk.device_id === deviceId && !opk.consumed_at) {
        if (!oldest || opk.uploaded_at < oldest.uploaded_at) {
          oldest = opk;
          oldestId = id;
        }
      }
    }
    
    if (oldest && oldestId) {
      oldest.consumed_at = Date.now();
      this.opks.set(oldestId, oldest);
      return oldest;
    }
    
    return undefined;
  }
}
```

## Monitoring and Alerts

### Health Metrics

```typescript
interface PrekeyHealthMetrics {
  device_id: string;
  spk_age_ms: number;
  spk_rotations_total: number;
  opk_count: number;
  opk_exhaustion_rate: number; // OPKs consumed per day
  opk_avg_age_ms: number;
  estimated_days_remaining: number;
  health_status: 'healthy' | 'warning' | 'critical';
}

class PrekeyMonitor {
  /**
   * Compute health metrics for a device.
   */
  async computeHealth(
    deviceId: string,
    server: PrekeyServer
  ): Promise<PrekeyHealthMetrics> {
    const spk = await server.getCurrentSpk(deviceId);
    const spkAge = Date.now() - spk.created_at;
    
    const opkCount = await server.getOpkCount(deviceId);
    const consumptionRate = await this.getConsumptionRate(deviceId, 7);
    const avgAge = await this.getAvgOpkAge(deviceId);
    
    const daysRemaining = consumptionRate > 0 
      ? opkCount / consumptionRate 
      : Infinity;
    
    const health = this.assessHealth(spkAge, opkCount, daysRemaining);
    
    return {
      device_id: deviceId,
      spk_age_ms: spkAge,
      spk_rotations_total: await server.getSpkRotationCount(deviceId),
      opk_count: opkCount,
      opk_exhaustion_rate: consumptionRate,
      opk_avg_age_ms: avgAge,
      estimated_days_remaining: daysRemaining,
      health_status: health,
    };
  }
  
  /**
   * Assess overall health status.
   */
  private assessHealth(
    spkAge: number,
    opkCount: number,
    daysRemaining: number
  ): 'healthy' | 'warning' | 'critical' {
    // Critical thresholds
    if (spkAge > 45 * 24 * 60 * 60 * 1000) return 'critical'; // SPK > 45 days
    if (opkCount < 5) return 'critical';
    if (daysRemaining < 1) return 'critical';
    
    // Warning thresholds
    if (spkAge > 30 * 24 * 60 * 60 * 1000) return 'warning'; // SPK > 30 days
    if (opkCount < 20) return 'warning';
    if (daysRemaining < 2) return 'warning';
    
    return 'healthy';
  }
  
  /**
   * Get OPK consumption rate (per day).
   */
  private async getConsumptionRate(
    deviceId: string,
    days: number
  ): Promise<number> {
    const consumed = await db.opks
      .where({ device_id: deviceId })
      .where('consumed_at', '>', Date.now() - days * 24 * 60 * 60 * 1000)
      .count();
    
    return consumed / days;
  }
  
  /**
   * Get average OPK age.
   */
  private async getAvgOpkAge(deviceId: string): Promise<number> {
    const opks = await db.opks
      .where({ device_id: deviceId })
      .where('consumed_at', null)
      .select();
    
    if (opks.length === 0) return 0;
    
    const totalAge = opks.reduce((sum, opk) => sum + (Date.now() - opk.uploaded_at), 0);
    return totalAge / opks.length;
  }
}
```

### Alert Configuration

```typescript
interface AlertConfig {
  spk_age_warning_ms: number;
  spk_age_critical_ms: number;
  opk_count_warning: number;
  opk_count_critical: number;
  days_remaining_warning: number;
  days_remaining_critical: number;
}

const DEFAULT_ALERT_CONFIG: AlertConfig = {
  spk_age_warning_ms: 30 * 24 * 60 * 60 * 1000,  // 30 days
  spk_age_critical_ms: 45 * 24 * 60 * 60 * 1000, // 45 days
  opk_count_warning: 20,
  opk_count_critical: 5,
  days_remaining_warning: 2,
  days_remaining_critical: 1,
};

class AlertManager {
  async checkAndAlert(metrics: PrekeyHealthMetrics): Promise<void> {
    const alerts: string[] = [];
    
    if (metrics.health_status === 'critical') {
      if (metrics.spk_age_ms > DEFAULT_ALERT_CONFIG.spk_age_critical_ms) {
        alerts.push(`CRITICAL: SPK age ${Math.floor(metrics.spk_age_ms / (24 * 60 * 60 * 1000))} days`);
      }
      if (metrics.opk_count < DEFAULT_ALERT_CONFIG.opk_count_critical) {
        alerts.push(`CRITICAL: Only ${metrics.opk_count} OPKs remaining`);
      }
      if (metrics.estimated_days_remaining < DEFAULT_ALERT_CONFIG.days_remaining_critical) {
        alerts.push(`CRITICAL: OPKs will exhaust in ${metrics.estimated_days_remaining.toFixed(1)} days`);
      }
    }
    
    if (alerts.length > 0) {
      await this.sendAlert({
        severity: 'critical',
        device_id: metrics.device_id,
        messages: alerts,
        metrics,
      });
    }
  }
  
  private async sendAlert(alert: any): Promise<void> {
    // Implementation: email, Slack, PagerDuty, etc.
    console.error('PREKEY ALERT:', JSON.stringify(alert, null, 2));
  }
}
```

## Automated Rotation

### Background Service

```typescript
class AutoRotationService {
  private checkInterval = 60 * 60 * 1000; // 1 hour
  private intervalId?: NodeJS.Timeout;
  
  start(manager: X3DHPrekeyManagerV1, server: PrekeyServer): void {
    console.log('Starting auto-rotation service');
    
    this.intervalId = setInterval(async () => {
      try {
        await this.performRotationCheck(manager, server);
      } catch (err) {
        console.error('Auto-rotation check failed:', err);
      }
    }, this.checkInterval);
  }
  
  stop(): void {
    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = undefined;
      console.log('Auto-rotation service stopped');
    }
  }
  
  private async performRotationCheck(
    manager: X3DHPrekeyManagerV1,
    server: PrekeyServer
  ): Promise<void> {
    // Check SPK age
    const currentSpk = await server.getCurrentSpk(manager.recipient_device_id);
    const age = Date.now() - currentSpk.created_at;
    
    if (age > SPK_MAX_AGE_MS) {
      console.log('Rotating SPK (age threshold exceeded)');
      manager.rotateSignedPrekey(Date.now());
      await server.publishBundle(manager.getPrekeyBundle());
    }
    
    // Check OPK count
    await checkAndRefillOpks(manager, server);
    
    // Compute and log health metrics
    const monitor = new PrekeyMonitor();
    const metrics = await monitor.computeHealth(manager.recipient_device_id, server);
    console.log(`Prekey health: ${metrics.health_status}`, metrics);
    
    // Check alerts
    const alertManager = new AlertManager();
    await alertManager.checkAndAlert(metrics);
  }
}
```

### Usage Example

```typescript
// In your application startup
const deviceId = 'alice-device-001';
const manager = await loadOrCreateIdentity(deviceId);
const server = new PrekeyServerClient();

// Start automated rotation
const rotationService = new AutoRotationService();
rotationService.start(manager, server);

// Graceful shutdown
process.on('SIGTERM', () => {
  rotationService.stop();
  process.exit(0);
});
```

## Fallback: SPK-Only Mode

If OPKs are exhausted, sessions can still be initialized using SPK only (reduced forward secrecy):

```typescript
// This is handled automatically by the library
const bundle = manager.getPrekeyBundle();

if (!bundle.opk_pub_b64) {
  console.warn('No OPKs available, using SPK-only mode');
  // Session will still work but with reduced forward secrecy
}

// X3DH will proceed without OPK
const { session_init, rk32 } = x3dhInitiatorV1({
  sender_device_id: 'alice-001',
  recipient_bundle: bundle, // Missing OPK
  initiator_ik_priv32: alice.ik.priv32,
});
```

⚠️ **Monitor SPK-only sessions** - Frequent fallback to SPK-only mode indicates:
- OPK under-provisioning
- High session initialization rate
- Refill automation not working

### Detecting SPK-Only Sessions

```typescript
// Server-side tracking
interface SessionInitEvent {
  timestamp: number;
  initiator_device_id: string;
  recipient_device_id: string;
  used_opk: boolean;
  spk_id: string | number;
}

function trackSessionInit(event: SessionInitEvent): void {
  db.sessionInits.insert(event);
  
  if (!event.used_opk) {
    console.warn(`SPK-only session: ${event.initiator_device_id} → ${event.recipient_device_id}`);
    
    // Check if this is a pattern
    const recentSpkOnly = db.sessionInits
      .where({ recipient_device_id: event.recipient_device_id })
      .where('timestamp', '>', Date.now() - 60 * 60 * 1000) // last hour
      .where('used_opk', false)
      .count();
    
    if (recentSpkOnly > 5) {
      alertManager.send({
        severity: 'warning',
        message: `High SPK-only session rate for ${event.recipient_device_id}`,
        count: recentSpkOnly,
      });
    }
  }
}
```

## Testing Rotation Logic

```typescript
import { describe, it, expect, beforeEach } from 'vitest';

describe('Prekey Rotation', () => {
  let manager: X3DHPrekeyManagerV1;
  
  beforeEach(() => {
    manager = new X3DHPrekeyManagerV1({ recipient_device_id: 'test-device' });
  });
  
  it('rotates SPK when age threshold exceeded', () => {
    const initialSpkId = Date.now();
    manager.rotateSignedPrekey(initialSpkId);
    
    const bundle1 = manager.getPrekeyBundle();
    expect(bundle1.spk_id).toBe(initialSpkId);
    
    // Simulate time passing
    const newSpkId = Date.now() + 10000;
    manager.rotateSignedPrekey(newSpkId);
    
    const bundle2 = manager.getPrekeyBundle();
    expect(bundle2.spk_id).toBe(newSpkId);
    expect(bundle2.spk_id).not.toBe(initialSpkId);
  });
  
  it('refills OPKs when count drops below threshold', () => {
    // Initial pool
    manager.addOneTimePrekeys({ startId: 1, count: 100 });
    
    // Consume most OPKs
    for (let i = 1; i <= 85; i++) {
      manager.consumeOneTimePrekey(i);
    }
    
    // Check remaining
    const bundle = manager.getPrekeyBundle();
    const remaining = 100 - 85;
    expect(remaining).toBeLessThan(OPK_LOW_THRESHOLD);
    
    // Refill
    manager.addOneTimePrekeys({ startId: 101, count: 50 });
    
    const bundleAfter = manager.getPrekeyBundle();
    expect(bundleAfter.opk_pub_b64).toBeDefined();
  });
  
  it('handles SPK-only mode when OPKs exhausted', () => {
    manager.rotateSignedPrekey(Date.now());
    // Don't add any OPKs
    
    const bundle = manager.getPrekeyBundle();
    expect(bundle.opk_pub_b64).toBeUndefined();
    expect(bundle.opk_id).toBeUndefined();
    
    // X3DH should still work without OPK
    expect(bundle.spk_pub_b64).toBeDefined();
    expect(bundle.spk_sig_b64).toBeDefined();
  });
});
```

## Production Checklist

Before deploying prekey rotation:

- [ ] Set SPK rotation interval (7-30 days)
- [ ] Set OPK pool size (100-200 per device)
- [ ] Set OPK refill threshold (20-30 keys)
- [ ] Set OPK expiry (90 days)
- [ ] Implement automated rotation service
- [ ] Configure health monitoring
- [ ] Set up alerting (email/Slack/PagerDuty)
- [ ] Test SPK rotation flow
- [ ] Test OPK refill flow
- [ ] Test SPK-only fallback
- [ ] Document server API endpoints
- [ ] Plan maintenance windows for bulk operations

## See Also

- [X3DHPrekeyManagerV1 API](../README.md#x3dh-prekey-lifecycle)
- [SPEC.md](./SPEC.md) - X3DH wire format
- [IDENTITY_PERSISTENCE.md](./IDENTITY_PERSISTENCE.md) - Identity key rotation
- [SESSION_LIFECYCLE.md](./SESSION_LIFECYCLE.md) - Session expiry policies

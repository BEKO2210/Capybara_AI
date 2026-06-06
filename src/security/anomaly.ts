import { sql } from 'drizzle-orm';
import type { AppDatabase } from '../db/client.js';
import { appendSecurityEvent } from '../audit/securityLog.js';

/**
 * Lightweight anomaly detection over the audit/security streams. Operator-level
 * (cross-tenant): it scans recent `security_events` and `audit_log` for
 * suspicious bursts and raises a tamper-evident `security.anomaly` event (and an
 * optional notification) so responders can act.
 *
 * Intentionally simple and explainable — threshold-over-window rules, not a
 * black-box model. Designed to run on a schedule (`npm run detect:anomalies`).
 */

export interface AnomalyThresholds {
  /** account lockouts (brute force) within the window. */
  authLockouts: number;
  /** oversight rejections (someone repeatedly trying blocked high-risk tools). */
  oversightRejections: number;
  /** key rotations (unexpected churn / possible attacker covering tracks). */
  keyRotations: number;
  /** role changes (privilege-escalation sweeps). */
  roleChanges: number;
}

export const DEFAULT_THRESHOLDS: AnomalyThresholds = {
  authLockouts: 5,
  oversightRejections: 5,
  keyRotations: 3,
  roleChanges: 5,
};

export interface DetectOptions {
  windowMs?: number;
  thresholds?: Partial<AnomalyThresholds>;
  now?: number;
  /** Optional notification sink (e.g. dispatch a webhook / page on-call). */
  notify?: (anomaly: Anomaly) => Promise<void> | void;
}

export interface Anomaly {
  kind: 'auth_lockout_burst' | 'oversight_rejection_burst' | 'key_rotation_burst' | 'privilege_change_burst';
  count: number;
  threshold: number;
  windowMinutes: number;
}

async function count(db: AppDatabase, query: ReturnType<typeof sql>): Promise<number> {
  const rows = (await db.execute(query)) as unknown as { n: string | number }[];
  return Number(rows[0]?.n ?? 0);
}

/** True if a security.anomaly of this kind was already raised within the window. */
async function alreadyRaised(db: AppDatabase, kind: string, sinceIso: string): Promise<boolean> {
  const n = await count(
    db,
    sql`SELECT count(*)::int AS n FROM security_events
        WHERE event_type = 'security.anomaly' AND created_at >= ${sinceIso}
          AND payload->>'kind' = ${kind}`,
  );
  return n > 0;
}

/**
 * Run detection. Returns the anomalies newly raised this pass. De-duplicated:
 * an anomaly of a given kind is raised at most once per window to avoid storms.
 */
export async function detectAnomalies(db: AppDatabase, opts: DetectOptions = {}): Promise<Anomaly[]> {
  const windowMs = opts.windowMs ?? 60 * 60_000;
  const now = opts.now ?? Date.now();
  const sinceIso = new Date(now - windowMs).toISOString();
  const windowMinutes = Math.round(windowMs / 60_000);
  const th = { ...DEFAULT_THRESHOLDS, ...opts.thresholds };

  const checks: Array<{ kind: Anomaly['kind']; count: number; threshold: number }> = [
    { kind: 'auth_lockout_burst', threshold: th.authLockouts, count: await count(db, sql`SELECT count(*)::int AS n FROM security_events WHERE event_type = 'auth.account_locked' AND created_at >= ${sinceIso}`) },
    { kind: 'oversight_rejection_burst', threshold: th.oversightRejections, count: await count(db, sql`SELECT count(*)::int AS n FROM security_events WHERE event_type = 'oversight.rejected' AND created_at >= ${sinceIso}`) },
    { kind: 'key_rotation_burst', threshold: th.keyRotations, count: await count(db, sql`SELECT count(*)::int AS n FROM security_events WHERE event_type = 'encryption.rotated' AND created_at >= ${sinceIso}`) },
    { kind: 'privilege_change_burst', threshold: th.roleChanges, count: await count(db, sql`SELECT count(*)::int AS n FROM audit_log WHERE action = 'user.role_changed' AND created_at >= ${sinceIso}`) },
  ];

  const raised: Anomaly[] = [];
  for (const c of checks) {
    if (c.count < c.threshold) continue;
    if (await alreadyRaised(db, c.kind, sinceIso)) continue;
    const anomaly: Anomaly = { kind: c.kind, count: c.count, threshold: c.threshold, windowMinutes };
    await appendSecurityEvent(db, {
      orgId: null,
      eventType: 'security.anomaly',
      severity: 'critical',
      payload: anomaly,
    });
    if (opts.notify) await opts.notify(anomaly);
    raised.push(anomaly);
  }
  return raised;
}

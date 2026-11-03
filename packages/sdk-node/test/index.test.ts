import { describe, expect, it } from 'vitest';
import { ProtectJS, SDK_VERSION } from '../src/index.js';

function createShield() {
  return new ProtectJS({
    projectId: 'project_test',
    policy: {
      schemaVersion: '1.0',
      policyVersion: '1.0',
      enforcementMode: 'monitor',
      defaults: {
        action: 'monitor',
        severity: 'low',
        maxRequestBodyBytes: 1024,
      },
      rules: [],
      routeExclusions: [],
      rateLimit: {
        enabled: false,
        windowSeconds: 60,
        maxRequests: 100,
        keyStrategy: 'ip',
      },
    },
    clock: () => new Date('2026-01-01T00:00:00.000Z'),
    eventId: () => 'event-1',
  });
}

describe('ProtectJS', () => {
  it('allows a clean request after running inspection', () => {
    const result = createShield().evaluate({ method: 'GET', path: '/health' });

    expect(result.detection.outcome).toBe('clean');
    expect(result.decision).toMatchObject({
      action: 'allow',
      ruleId: 'policy.allow',
      category: 'policy',
      reason: { code: 'no_indicator_detected' },
    });
    expect(result.event).toMatchObject({
      eventId: 'event-1',
      projectId: 'project_test',
      sdkVersion: SDK_VERSION,
      request: { method: 'GET', route: '/health' },
    });
  });

  it('evaluates query indicators instead of returning the policy default', () => {
    const result = createShield().evaluate({
      method: 'GET',
      path: '/search',
      query: { q: 'UNION SELECT username FROM users' },
    });

    expect(result.detection.findings[0]).toMatchObject({
      ruleId: 'input.sql_injection_indicator',
    });
    expect(result.decision.ruleId).toBe('input.sql_injection_indicator');
    expect(result.decision.reason.code).toBe('indicator_monitored_by_policy');
  });
});

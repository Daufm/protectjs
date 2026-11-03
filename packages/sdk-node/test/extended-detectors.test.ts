import { describe, expect, it } from 'vitest';
import { DetectionEngine, RedisAtomicCounterStore } from '../src/index.js';

const engine = new DetectionEngine();

describe('extended detectors', () => {
  it('detects additional SQL timing and file indicators', () => {
    const result = engine.inspect({
      method: 'POST',
      route: '/q',
      query: {
        mssql: "'; WAITFOR DELAY '0:0:5'--",
        postgres: '1; SELECT pg_sleep(5)',
        outfile: "UNION SELECT 1 INTO OUTFILE '/tmp/x'",
      },
    });

    expect(result.findings.map((finding) => finding.reasonCode)).toEqual(
      expect.arrayContaining(['sql_timing_function', 'sql_dangerous_function']),
    );
  });

  it('detects entity-encoded XSS and extra NoSQL operators', () => {
    const result = engine.inspect({
      method: 'POST',
      route: '/form',
      query: { html: '&lt;script&gt;alert(1)&lt;/script&gt;' },
      body: { filter: { $or: [{ $function: '1' }] } },
    });

    expect(result.findings.map((finding) => finding.ruleId)).toEqual(
      expect.arrayContaining([
        'input.nosql_injection_indicator',
        'input.xss_indicator',
      ]),
    );
  });

  it('detects template, header, XXE, LDAP, file-scheme SSRF, and Windows paths', () => {
    const result = engine.inspect({
      method: 'POST',
      route: '/ingest',
      query: {
        template: '${jndi:ldap://127.0.0.1/a}',
        redirect: 'ok\r\nLocation: https://evil.example',
        ldap: '*)(uid=*))(|(uid=*',
        file: 'file:///etc/passwd',
        win: 'C:\\Windows\\system32\\config\\sam',
      },
      body: {
        xml: '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
      },
    });

    expect(result.findings.map((finding) => finding.ruleId).sort()).toEqual(
      [
        'input.header_injection_indicator',
        'input.ldap_injection_indicator',
        'input.path_traversal_indicator',
        'input.ssrf_indicator',
        'input.template_injection_indicator',
        'input.xxe_indicator',
      ].sort(),
    );
  });

  it('does not flag ordinary business content for the new rules', () => {
    const result = engine.inspect({
      method: 'POST',
      route: '/orders',
      body: {
        note: 'Please email uid=warehouse when the objectclass is ready.',
        xml: '<note>thanks</note>',
        next: '/account',
      },
    });

    expect(result.findings).toEqual([]);
  });
});

describe('RedisAtomicCounterStore', () => {
  it('increments through a host-provided eval client', async () => {
    const store = new RedisAtomicCounterStore({
      eval: async (_script, _keys, args) => [2, Number(args[0])],
    });
    const now = Date.parse('2026-01-01T00:00:00.000Z');
    await expect(store.increment('user:1', 60, now)).resolves.toEqual({
      count: 2,
      resetAt: now + 60_000,
      limit: Number.MAX_SAFE_INTEGER,
    });
  });
});

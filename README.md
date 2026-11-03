# EthioShield

[![CI](https://github.com/Daufm/etshield/actions/workflows/ci.yml/badge.svg)](https://github.com/Daufm/etshield/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](./LICENSE)

Open-source Node.js SDK for **local request inspection**, policy evaluation, rate limiting, and Express protection.

EthioShield inspects normalized request values and emits structured findings. Use it as an application-layer control in monitor or block mode. It is **not** a network WAF and **not** a replacement for parameterized queries, output encoding, or authorization checks.

## Packages

| Package                                                            | Description                                                     |
| ------------------------------------------------------------------ | --------------------------------------------------------------- |
| [`@ethioshield/sdk-node`](./packages/sdk-node)                     | Detection engine, policy evaluation, Express middleware, stores |
| [`@ethioshield/security-contracts`](./packages/security-contracts) | Versioned event, decision, and policy types                     |
| [`@ethioshield/playground`](./apps/playground)                     | Minimal Express example (not published)                         |

## Install

Requires **Node.js 20+**. The SDK is ESM-only.

```bash
npm install @ethioshield/sdk-node @ethioshield/security-contracts
```

Express 4 or 5 is an optional peer dependency if you use `protect()`.

## Quick start (Express)

```ts
import express from 'express';
import { EthioShield } from '@ethioshield/sdk-node';

const app = express();
const shield = new EthioShield({
  projectId: 'app',
  mode: 'monitor', // start here; switch to 'block' after reviewing findings
  policy: {
    schemaVersion: '1.0',
    policyVersion: '1.0',
    enforcementMode: 'monitor',
    defaults: { action: 'monitor', severity: 'low', maxRequestBodyBytes: 1_048_576 },
    rules: [],
    routeExclusions: [{ route: '/health', methods: ['GET'] }],
    rateLimit: { enabled: false, windowSeconds: 60, maxRequests: 100, keyStrategy: 'ip' },
  },
});

app.use(express.json({ limit: '1mb' }));
app.use(shield.protect());
```

Mount a bounded parser **before** `protect()` when you want JSON or urlencoded bodies inspected. The SDK never reads the request stream itself.

### Framework-agnostic inspection

Apps that are not on Express can call the engine directly:

```ts
import { DetectionEngine, evaluateRequest } from '@ethioshield/sdk-node';

const engine = new DetectionEngine();
const result = engine.inspect({
  method: 'GET',
  route: '/search',
  query: { q: "1' OR '1'='1" },
});

const evaluation = evaluateRequest({
  projectId: 'app',
  policy, // same policy document as above
  request: { method: 'GET', path: '/search', query: { q: "1' OR '1'='1" } },
  engine,
});
```

## Detection coverage

Built-in detectors produce **request indicators** (heuristic). They do not prove that a sink was exploited.

| Detector                  | Rule ID                               |
| ------------------------- | ------------------------------------- |
| SQL injection             | `input.sql_injection_indicator`       |
| NoSQL injection           | `input.nosql_injection_indicator`     |
| XSS                       | `input.xss_indicator`                 |
| Path traversal            | `input.path_traversal_indicator`      |
| Command injection         | `input.command_injection_indicator`   |
| SSRF                      | `input.ssrf_indicator`                |
| Prototype pollution       | `input.prototype_pollution_indicator` |
| Open redirect             | `input.open_redirect_indicator`       |
| Template injection / JNDI | `input.template_injection_indicator`  |
| HTTP header injection     | `input.header_injection_indicator`    |
| XXE                       | `input.xxe_indicator`                 |
| LDAP injection            | `input.ldap_injection_indicator`      |

Custom synchronous plugins can be passed into `DetectionEngine`.

## Production use

This 0.1.x line is intended for real applications with the following contract:

1. Roll out in **monitor** mode, review false positives, then enable **block** on specific routes or rules.
2. Multi-instance deployments must inject an atomic store (`RedisAtomicCounterStore` or your own `AtomicCounterStore`). The in-memory store is single-process only.
3. Supply `trustedIdentity` yourself. Client IP is used only when `trustedProxy` is configured.
4. Multipart, cookies, and most headers are out of scope unless you pass parsed values into `inspect()`.
5. Findings are indicators, not exploit proof. Keep parameterized queries, encoding, and auth in the application.

There is no bundled cloud dashboard, CAPTCHA provider, or paid IP intelligence. Those remain optional host adapters.

## Development

```bash
npm ci
npm run validate
```

| Command                                            | Purpose                                                       |
| -------------------------------------------------- | ------------------------------------------------------------- |
| `npm test`                                         | Unit tests                                                    |
| `npm run test:coverage`                            | Coverage gates (70% statements/lines/functions, 60% branches) |
| `npm run test:integration`                         | Playground HTTP tests                                         |
| `npm run test:exports` / `npm run check:artifacts` | Published package shape                                       |
| `npm run audit:production`                         | High/critical production dependency audit                     |

## Versioning

- SDK packages use semantic versions. Current public line: **0.1.0**.
- Security contracts use `major.minor` schema versions (currently `1.0`).
- Telemetry events never include secrets, cookies, authorization headers, or raw bodies.

## Community

- [Contributing](./CONTRIBUTING.md)
- [Code of conduct](./CODE_OF_CONDUCT.md)
- [Security policy](./SECURITY.md)
- [Changelog](./CHANGELOG.md)
- License: [Apache-2.0](./LICENSE)

## Status of historical design notes

`EthioShield-Security-Audit.md`, `DetectionEngine-v2-Architecture-Review.md`, and `Milestone-Completion-and-Security-Evidence-Report.md` are **historical working documents**. Detector coverage in this tree is newer than those reports.

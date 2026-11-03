# ProtectJS

[![CI](https://github.com/Daufm/etshield/actions/workflows/ci.yml/badge.svg)](https://github.com/Daufm/etshield/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](./LICENSE)

Open-source Node.js SDK for **local request inspection**, policy evaluation, rate limiting, and Express protection.

ProtectJS inspects normalized request values and emits structured findings. Use it as an application-layer control in monitor or block mode. It is **not** a network WAF and **not** a replacement for parameterized queries, output encoding, or authorization checks.

## Packages

| Package                                                          | Description                                                     |
| ---------------------------------------------------------------- | --------------------------------------------------------------- |
| [`@protectjs/sdk-node`](./packages/sdk-node)                     | Detection engine, policy evaluation, Express middleware, stores |
| [`@protectjs/security-contracts`](./packages/security-contracts) | Versioned event, decision, and policy types                     |
| [`@protectjs/playground`](./apps/playground)                     | Minimal Express example (not published)                         |

## Install

Requires **Node.js 20+**. The SDK is ESM-only.

```bash
npm install @protectjs/sdk-node @protectjs/security-contracts
```

Express 4 or 5 is an optional peer dependency if you use `protect()`.

## Quick start (Express)

```ts
import express from 'express';
import { ProtectJS } from '@protectjs/sdk-node';

const app = express();
const shield = new ProtectJS({
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
import { DetectionEngine, evaluateRequest } from '@protectjs/sdk-node';

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

## Where ProtectJS is strong

| Strength                | What it provides                                                                                      |
| ----------------------- | ----------------------------------------------------------------------------------------------------- |
| Lightweight integration | A small runtime dependency footprint and a straightforward Node.js API                                |
| Request inspection      | Bounded normalization and detection across query, route, body, and selected headers                   |
| Broad detector coverage | Indicators for SQL injection, XSS, SSRF, NoSQL injection, path traversal, command injection, and more |
| Express support         | Monitor or block middleware with framework-agnostic engine access                                     |
| Operational controls    | In-memory or Redis-backed rate limiting, correlation, budgets, and failure handling                   |
| Extensibility           | Custom detectors, policy evaluation, instrumentation, telemetry, and storage adapters                 |

## Compared with other tools

ProtectJS complements rather than replaces specialized policy, authorization, observability, and rate-limiting tools.

| Tool                      | Primary focus                                 | ProtectJS difference                                                                                                  |
| ------------------------- | --------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| FortressJS                | Node.js application and API security          | ProtectJS focuses on bounded request indicators, policy evaluation, and extensible Node.js middleware                 |
| Ratelane                  | Rate limiting and traffic control             | ProtectJS includes rate limiting, but also provides request inspection and security detectors                         |
| Open Policy Agent (OPA)   | General-purpose, centralized policy decisions | OPA is broader and stronger for organization-wide policy; ProtectJS is simpler to embed directly in a Node.js process |
| Cerbos                    | Identity-aware authorization                  | Cerbos is stronger for RBAC/ABAC authorization; ProtectJS focuses on suspicious input and request behavior            |
| express-rate-limit        | Basic Express rate limiting                   | ProtectJS provides a broader security surface; express-rate-limit is simpler when throttling is the only requirement  |
| OpenTelemetry Node.js SDK | Traces, metrics, and logs                     | OpenTelemetry is an observability standard; ProtectJS produces security findings that can be connected to telemetry   |

ProtectJS detectors are heuristic indicators, not proof of exploitation. Continue using parameterized queries, output encoding, authentication, authorization, and other application security controls.

## ProtectJS future/updatable

Planned areas for future releases include:

- More accurate, context-aware detectors with improved false-positive controls.
- Additional framework adapters beyond Express.
- OpenTelemetry integration for security findings and decision events.
- More policy examples, plugin documentation, and runnable starter projects.
- Benchmarks and regression fixtures using intentionally vulnerable applications.
- Optional integrations for external telemetry, identity, and rate-limit providers.
- Clearer security metrics and operational dashboards through host adapters.

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

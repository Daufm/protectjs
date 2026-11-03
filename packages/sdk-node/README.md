# @protectjs/sdk-node

Open-source Node.js SDK for ProtectJS: local request inspection, policy evaluation, Express middleware, rate limiting, and opt-in instrumentation.

```bash
npm install @protectjs/sdk-node
```

Requires Node.js 20+. ESM only. Express 4 or 5 is optional and needed only for `protect()`.

## Express

```ts
import express from 'express';
import { ProtectJS } from '@protectjs/sdk-node';

const shield = new ProtectJS({
  projectId: 'app',
  mode: 'monitor',
  policy: {
    /* SecurityPolicy 1.0 document */
  },
});

const app = express();
app.use(express.json({ limit: '1mb' }));
app.use(shield.protect());
```

`protect()` inspects route, query, params, parsed body, and a small sanitized header set. Default mode is monitor. `mode: 'block'` returns `403` for findings and `503` when inspection fails closed.

## Engine-only (any framework)

```ts
import { DetectionEngine, evaluateRequest } from '@protectjs/sdk-node';

const engine = new DetectionEngine();
const detection = engine.inspect({
  method: 'POST',
  route: '/login',
  body: { user: { $ne: '' } },
});

const { decision, event } = evaluateRequest({
  projectId: 'app',
  policy,
  request: { method: 'POST', path: '/login', body: { user: { $ne: '' } } },
  engine,
});
```

`ProtectJS.evaluate()` uses the same path: it runs the detection engine and policy evaluator, it does not return a dummy default decision.

## Multi-instance rate limits

```ts
import { RedisAtomicCounterStore } from '@protectjs/sdk-node';
import { createClient } from 'redis';

const redis = createClient();
await redis.connect();

const store = new RedisAtomicCounterStore({
  eval: (script, keys, args) => redis.eval(script, { keys: [...keys], arguments: [...args] }),
});
```

Pass `store` as `rateLimit.store` when constructing `ProtectJS`. `InMemoryAtomicCounterStore` is for a single process.

## Built-in detectors

SQL, NoSQL, XSS, path traversal, command injection, SSRF, prototype pollution, open redirect, template/JNDI, CRLF header injection, XXE, and LDAP filter injection. All are bounded heuristics. See the repository README for the full contract and rollout guidance.

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

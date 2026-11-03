# @ethioshield/sdk-node

Open-source Node.js SDK for EthioShield: local request inspection, policy evaluation, Express middleware, rate limiting, and opt-in instrumentation.

```bash
npm install @ethioshield/sdk-node
```

Requires Node.js 20+. ESM only. Express 4 or 5 is optional and needed only for `protect()`.

## Express

```ts
import express from 'express';
import { EthioShield } from '@ethioshield/sdk-node';

const shield = new EthioShield({
  projectId: 'app',
  mode: 'monitor',
  policy: { /* SecurityPolicy 1.0 document */ },
});

const app = express();
app.use(express.json({ limit: '1mb' }));
app.use(shield.protect());
```

`protect()` inspects route, query, params, parsed body, and a small sanitized header set. Default mode is monitor. `mode: 'block'` returns `403` for findings and `503` when inspection fails closed.

## Engine-only (any framework)

```ts
import { DetectionEngine, evaluateRequest } from '@ethioshield/sdk-node';

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

`EthioShield.evaluate()` uses the same path: it runs the detection engine and policy evaluator, it does not return a dummy default decision.

## Multi-instance rate limits

```ts
import { RedisAtomicCounterStore } from '@ethioshield/sdk-node';
import { createClient } from 'redis';

const redis = createClient();
await redis.connect();

const store = new RedisAtomicCounterStore({
  eval: (script, keys, args) =>
    redis.eval(script, { keys: [...keys], arguments: [...args] }),
});
```

Pass `store` as `rateLimit.store` when constructing `EthioShield`. `InMemoryAtomicCounterStore` is for a single process.

## Built-in detectors

SQL, NoSQL, XSS, path traversal, command injection, SSRF, prototype pollution, open redirect, template/JNDI, CRLF header injection, XXE, and LDAP filter injection. All are bounded heuristics. See the repository README for the full contract and rollout guidance.

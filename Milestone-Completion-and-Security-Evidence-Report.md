# EthioShield Milestone Completion and Security Evidence Report

**Repository:** `Daufm/etshield`  
**SDK version:** `0.1.0-alpha.0`  
**Report date:** 2026-10-31  
**Scope:** Detection Engine v2 milestones implemented in the current worktree  
**Release status:** Experimental; not production-ready

## 1. Executive summary

EthioShield currently provides a bounded, opt-in Node.js/TypeScript request
inspection SDK with Express integration. The implementation has progressed
through the approved Detection Engine v2 sequence:

1. Contract and evidence baseline
2. Enforcement correctness and body-state handling
3. Canonicalization and parser provenance
4. Structured detector adapters
5. Sink observation and exploitability correlation
6. Stateful behavioral correlation hardening
7. Operational qualification

The repository contains tested request indicators for SQL injection, NoSQL
operator injection, executable HTML/XSS patterns, and path traversal. It also
contains policy evaluation, body-state handling, rate limiting, behavioral
correlation, opt-in sink observers, bounded resource controls, and package
release checks.

These capabilities do **not** make EthioShield a complete WAF, static
analyzer, dependency scanner, authentication system, authorization system, or
proof of exploitability. Sink correlation is an explicit host integration
signal and remains subject to the correctness of the host-provided
instrumentation.

No commit, push, publish, or deployment was performed for the work covered by
this report.

## 2. Milestone completion matrix

| Milestone                                            | Status                                  | Primary evidence                                                                                                                                                                                    | Security result                                                                                        |
| ---------------------------------------------------- | --------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| M1 — Contract and evidence baseline                  | Complete                                | [detection types](packages/sdk-node/src/detection/types.ts), [engine](packages/sdk-node/src/detection/engine.ts), policy tests                                                                      | Inspection states, bounded errors, invalid-finding rejection, cooperative budget reporting             |
| M2 — Enforcement correctness and body-state handling | Complete                                | [Express middleware](packages/sdk-node/src/express.ts), [Express tests](packages/sdk-node/test/express.test.ts)                                                                                     | Explicit body states, deterministic block/monitor handling, observable exclusions                      |
| M3 — Canonicalization and parser provenance          | Complete                                | [normalization](packages/sdk-node/src/detection/normalization.ts), [parser differential tests](packages/sdk-node/test/parser-differential.test.ts)                                                  | Bounded raw/canonical records, one decode pass, provenance, ambiguity errors                           |
| M4 — Structured detector adapters                    | Complete                                | [detector utilities](packages/sdk-node/src/detection/detector-utils.ts), detector modules, [detection tests](packages/sdk-node/test/detection.test.ts)                                              | Bounded token/tag/operator/segment parsing; existing rule IDs preserved                                |
| M5 — Sink observation and exploitability correlation | Complete with host integration required | [sink correlation](packages/sdk-node/src/detection/sink-correlation.ts), [instrumentation](packages/sdk-node/src/instrumentation.ts), [sink tests](packages/sdk-node/test/sink-correlation.test.ts) | Request indicators remain distinct from sink observations; mismatches/failures do not upgrade findings |
| M6 — Stateful behavioral correlation hardening       | Complete                                | [correlation](packages/sdk-node/src/correlation.ts), [rate-limit key encoding](packages/sdk-node/src/rate-limit/key.ts), [hardening tests](packages/sdk-node/test/stateful-key-hardening.test.ts)   | Length-prefixed keys, TTL eviction, bounded cardinality, deterministic store failure behavior          |
| M7 — Operational qualification                       | Complete as a regression gate           | [operational tests](packages/sdk-node/test/operational-hardening.test.ts), package scripts and release guidance                                                                                     | Sustained bounded-input checks, staged rollout semantics, artifact/export/audit gates                  |

The milestone labels above follow the user-approved sequence. The
architecture review uses `M1`–`M6` after its baseline section; this report uses
the user-facing seven-item sequence.

## 3. Implementation evidence

### 3.1 Contracts and inspection states

Verified in [types.ts](packages/sdk-node/src/detection/types.ts),
[detection contracts](packages/security-contracts/src/detection.ts), and
[engine.ts](packages/sdk-node/src/detection/engine.ts):

- Detection results distinguish `complete`, `error`, and `inconclusive`.
- Inspection errors include parser, normalization, malformed encoding,
  detector, invalid finding, budget, body-unavailable, and ambiguous
  representation conditions.
- Plugin findings are runtime-validated for bounded identifiers, supported
  categories/components/severities, and confidence range.
- Finding count and normalized-value count are bounded.
- `maxDurationMs` is a cooperative budget. It does not interrupt synchronous
  JavaScript detector code.
- Non-clean inspection results are passed to fail-safe policy evaluation.

### 3.2 Enforcement and body handling

Verified in [express.ts](packages/sdk-node/src/express.ts) and
[express.test.ts](packages/sdk-node/test/express.test.ts):

- Body states include `absent`, `parsed`, `malformed`, `unavailable`, and
  `streaming`.
- The SDK does not read, buffer, or replay request streams.
- Block mode returns controlled `503` responses for relevant inspection
  failures.
- Monitor mode continues with an explicit non-clean decision.
- Route exclusions are method-aware and emit policy decision/telemetry
  records.
- Telemetry and callback failures do not silently convert a security decision
  into a clean result.

The current body-state inference is an Express-boundary heuristic. Host parser
ordering and parser behavior remain integration responsibilities.

### 3.3 Canonicalization and provenance

Verified in [normalization.ts](packages/sdk-node/src/detection/normalization.ts)
and [parser-differential.test.ts](packages/sdk-node/test/parser-differential.test.ts):

- Values retain a bounded raw representation in the in-process detection
  context.
- Canonical values record one percent-decoding pass, Unicode NFKC
  normalization, and deterministic case folding.
- Each normalized value records decode depth, transformations, parser
  identity/version, duplicate status, truncation, and ambiguity.
- A second valid percent-encoded layer is reported as
  `ambiguous_representation`; it is not recursively decoded until stable.
- HTML entities, SQL literals, and filesystem semantics are not globally
  decoded.
- Raw values are not included in security events or sink metadata.

The query adapter accepts already-parsed values and preserves duplicate values
as arrays. The JSON adapter uses bounded parsing but does not claim complete
duplicate-key detection for every upstream parser configuration.

### 3.4 Structured request indicators

Verified in the detector modules and [detector-utils.ts](packages/sdk-node/src/detection/detector-utils.ts):

- SQL input uses bounded tokenization with quote and block-comment handling.
- NoSQL input uses an allowlisted operator grammar.
- HTML/XSS input uses bounded tag and executable-attribute parsing plus
  dangerous scheme checks.
- Path traversal input uses bounded segment parsing across slash and
  backslash separators.
- Existing rule IDs, detector ordering, confidence bands, and deduplication
  remain stable.
- Findings contain classifications and evidence identifiers, not matched
  request payloads.

These detectors are heuristic request indicators. They do not prove that a
database, template renderer, filesystem API, command shell, or other sink will
interpret the input dangerously.

### 3.5 Sink observation and correlation

Verified in [instrumentation.ts](packages/sdk-node/src/instrumentation.ts),
[sink-correlation.ts](packages/sdk-node/src/detection/sink-correlation.ts), and
[sink-correlation.test.ts](packages/sdk-node/test/sink-correlation.test.ts):

- Sink observers are explicit and opt-in.
- Supported observer classes include SQL, outbound HTTP, filesystem,
  command, and authorization observations.
- Observer inputs are bounded and classification-based.
- Observer calls have bounded cooperative delivery timeouts and isolated
  error results.
- No global runtime API is monkey-patched.
- Correlation requires matching request and sink correlation IDs.
- Failed, timed-out, absent, or mismatched observations do not upgrade a
  request indicator.
- Correlation output excludes raw SQL, bodies, command arguments, credentials,
  and paths.

The `correlated_exploitability` status means that a request indicator and a
matching host-provided sink observation were correlated. It is not a
cryptographic proof or complete exploitability proof. The host must correctly
invoke the observer at the relevant sink and preserve the correlation ID.

### 3.6 Stateful correlation and rate limiting

Verified in [correlation.ts](packages/sdk-node/src/correlation.ts),
[limiter.ts](packages/sdk-node/src/rate-limit/limiter.ts), [key.ts](packages/sdk-node/src/rate-limit/key.ts),
and [stateful-key-hardening.test.ts](packages/sdk-node/test/stateful-key-hardening.test.ts):

- Keys use bounded length-prefixed components.
- Delimiter-bearing identities cannot create equivalent serialized keys.
- Local stores evict expired entries before cardinality checks.
- Cardinality exhaustion produces configured deterministic monitor/block
  behavior.
- Correlation supports route, authenticated-subject, target-account, risk, and
  IP dimensions according to configured rules.
- IP is not substituted for missing trusted identity.
- Shared deployments require an atomic store with equivalent key, TTL,
  cardinality, and failure semantics.

## 4. Security evidence and validation

The final validation run completed with:

| Check                      | Result                                                                 |
| -------------------------- | ---------------------------------------------------------------------- |
| `npm run lint`             | Passed                                                                 |
| `npm run typecheck`        | Passed                                                                 |
| `npm test`                 | **82 tests passed**                                                    |
| `npm run test:integration` | **2 tests passed**                                                     |
| `npm run test:coverage`    | **82 tests passed**                                                    |
| Coverage                   | **85.89% statements, 84.69% branches, 93.60% functions, 85.89% lines** |
| `npm run build`            | Passed                                                                 |
| `npm run test:exports`     | Passed; both built ESM entry points loaded                             |
| `npm run check:artifacts`  | Passed; source and tests excluded from package artifacts               |
| `npm run audit:production` | Passed; **0 runtime dependency vulnerabilities**                       |
| Targeted Prettier checks   | Passed                                                                 |
| `git diff --check`         | Passed                                                                 |

The full development dependency audit is a separate concern. Development
tooling findings, if present, must be reviewed before a release candidate and
must not be represented as a clean full dependency audit.

The measured tests are regression checks, not production capacity benchmarks.
The repository does not yet establish latency SLOs, maximum deployment
throughput, detector recall, or false-positive rates across representative
traffic.

## 5. Security guarantees currently supported

The current implementation supports the following bounded guarantees when
configured and integrated correctly:

1. Request inspection does not silently become clean after parser, detector,
   normalization, or budget failures.
2. Finding output is bounded, validated, deduplicated, and does not include
   matched payloads.
3. Express block-mode inspection failures receive controlled responses.
4. Monitor/block policy behavior is explicit and testable.
5. Route exclusions are observable policy exceptions.
6. Local rate-limit and correlation state has bounded cardinality and TTL
   behavior.
7. Sink observers are opt-in, bounded, sanitized, and failure-isolated.
8. Package validation rejects source/test leakage from published artifacts.
9. Runtime dependency audit and reproducible lockfile checks are available.

These guarantees depend on trusted middleware placement, trusted identity
callbacks, correct parser configuration, appropriate policy configuration, and
an atomic shared store when running across multiple processes.

## 6. Explicit non-guarantees and unsupported classes

The current SDK does not implement or claim:

- Authentication or authorization enforcement
- SSRF prevention
- Command injection prevention
- XXE prevention
- CSRF protection
- Webhook signature verification
- Dependency or supply-chain vulnerability detection
- Static code analysis
- Complete SQL, NoSQL, XSS, or path traversal coverage
- Automatic sink instrumentation
- Hard interruption of synchronous JavaScript detectors
- Distributed counter correctness without a compatible shared store
- Complete duplicate-key semantics across all host parsers
- Spoof-resistant client/device fingerprinting
- Complete production WAF behavior

Request indicators must not be interpreted as verified sink-level
exploitability without a correctly integrated sink observer.

## 7. Release and rollout recommendation

This worktree should remain an experimental release candidate, not a
production security dependency. Before any release:

1. Review all uncommitted changes and create a focused commit.
2. Run the complete validation command set from
   [README.md](README.md).
3. Review the full development dependency audit separately from the runtime
   audit.
4. Validate middleware ordering with the target application's JSON,
   URL-encoded, multipart, and streaming parsers.
5. Confirm trusted proxy and identity assumptions.
6. Confirm telemetry and observer redaction at the host integration boundary.
7. Start in monitor mode with representative traffic.
8. Review false positives, inspection failures, store errors, memory pressure,
   and event volume.
9. Enable narrowly scoped throttling or blocking only after review.
10. Maintain an application-level emergency disable path.

## 8. Outstanding security work

The following work remains before a production security claim would be
credible:

- Independent adversarial review of the complete uncommitted diff
- Host-parser differential testing for the target deployment stack
- Explicit duplicate JSON-key and proxy/application canonicalization policy
- Sink integration tests against real host adapters
- Distributed shared-store correctness and outage testing
- Load testing under representative traffic and concurrency
- Privacy review for identity, route, telemetry, and sink metadata
- Dependency-update and development-audit remediation
- Authentication, authorization, webhook, SSRF, CSRF, and supply-chain
  controls appropriate to the host application

## 9. Worktree and provenance note

At report creation time, the repository contains modifications from the
Detection Engine v2 milestones plus the untracked architecture and audit
documents. This report is also a new repository-local document. No unrelated
work was reverted, and no generated secrets, API keys, credentials, or
request bodies were added.

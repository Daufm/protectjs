# Changelog

All notable changes to this project are documented in this file.

## 0.1.0 — 2026-11-03

### Added

- Public OSS packaging for `@protectjs/sdk-node` and `@protectjs/security-contracts` (license metadata, repository fields, Apache-2.0 in published files).
- GitHub community files: contributing guide, code of conduct, security policy, changelog, issue and pull-request templates.
- Framework-agnostic `evaluateRequest()` that runs the detection engine and policy evaluator.
- `RedisAtomicCounterStore` adapter (bring your own Redis `eval` client) for multi-instance rate limits.
- Detectors for template/JNDI injection, CRLF header injection, XXE, and LDAP filter injection.
- Express 4 and 5 as optional peer dependencies; Node.js 20+ engines.

### Changed

- First public version is `0.1.0` (replaces `0.1.0-alpha.0`).
- `ProtectJS.evaluate()` inspects the request instead of always returning the policy default.
- Playground uses `protect()` with a JSON parser, matching the documented Express integration.
- README and package docs describe an installable SDK with explicit heuristic limits, not a “do not use” prototype.
- SQL, XSS, NoSQL, path, command, and SSRF detectors cover additional bounded indicator shapes.

### Security

- SQL tokenizer treats MySQL `#` comments as syntax, and flags WAITFOR/pg_sleep and a small set of dangerous file/command functions.
- XSS inspects HTML-entity-decoded copies, `vbscript:` / `data:` javascript schemes, and a wider dangerous-tag set.
- NoSQL operator set includes `$or`, `$function`, `$lookup`, and related operators.
- SSRF flags `file:`, `gopher:`, and `dict:` URLs in addition to private/metadata hosts.

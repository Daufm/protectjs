# Contributing to EthioShield

Thanks for helping improve this SDK.

## Development setup

- Node.js 20 or newer
- npm 10 or newer (`packageManager` is pinned in the root `package.json`)

```bash
git clone https://github.com/Daufm/etshield.git
cd etshield
npm ci
npm run validate
```

## Project layout

- `packages/security-contracts` — shared types and validators
- `packages/sdk-node` — detection engine and Express integration
- `apps/playground` — example Express app used by integration tests

## Pull requests

1. Open an issue first for large detector or API changes.
2. Keep findings as indicators with stable `ruleId` values unless you are intentionally introducing a new rule.
3. Add or update tests next to the change (`packages/sdk-node/test`).
4. Run `npm run validate` before opening the PR.
5. Do not include secrets, production traffic, or exploit payloads against third-party systems.

## Detector changes

Detectors must stay bounded (length, depth, token, and duration limits). Prefer structured parsing over a single broad regular expression. New rules should include:

- at least one true-positive fixture
- at least one ordinary business-value negative fixture
- a reason code that does not embed raw user input

## Code style

The repo uses Prettier and ESLint. `npm run validate` includes `format:check` and `lint`.

## License

Contributions are accepted under the Apache License 2.0.

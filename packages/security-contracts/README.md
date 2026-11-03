# @protectjs/security-contracts

Versioned TypeScript contracts for ProtectJS security events, decisions, and policies.

```bash
npm install @protectjs/security-contracts
```

Current schema version: `1.0`.

- A new **major** version may remove or rename fields.
- A new **minor** version may add optional fields when consumers have a fallback.
- Runtime validators reject unsupported versions and unknown fields at trust boundaries.

Telemetry types exclude secrets, passwords, authorization headers, cookies, payment data, and raw request bodies.

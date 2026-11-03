# Security Policy

## Supported versions

| Version | Supported |
| ------- | --------- |
| 0.1.x   | Yes       |
| < 0.1.0 | No        |

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability.

Use [GitHub private vulnerability reporting](https://github.com/Daufm/etshield/security/advisories/new) on this repository. Include:

- a concise description
- affected files, versions, or commit identifiers
- reliable reproduction that does not access third-party data
- potential impact

Do not include secrets or personal data in a report.

We aim to acknowledge reports within 7 days and to share a remediation plan or status update within 30 days.

## Scope

ProtectJS findings are request indicators. A detector miss is expected for some encodings and dialects; please report misses that are reliable, bounded, and not already documented as out of scope (DNS rebinding, multipart bodies the host never parsed, and similar host-integration gaps).

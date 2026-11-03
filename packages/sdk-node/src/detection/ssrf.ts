// src/detection/ssrf.ts

/*
 * Bounded SSRF detector. Delegates authority parsing to the WHATWG URL
 * parser (global `URL`, no network access) instead of a hand-rolled regex,
 * because that parser already separates userinfo/host/port correctly and
 * canonicalizes decimal/octal/hex/shorthand IPv4 host forms into standard
 * dotted-decimal — the class of bug a manual regex is prone to (see the
 * bypasses this replaced). Only the parsed hostname is ever matched; it is
 * never included in findings.
 *
 * KNOWN LIMITATIONS (out of scope for a bounded, static-string detector):
 *  - Cannot detect a public domain that resolves to an internal IP via DNS
 *    (DNS rebinding) — no DNS lookups are performed.
 *  - Does not inspect URLs embedded inside another URL's query string
 *    (e.g. an open-redirect parameter chaining to an internal target).
 *  - Host-based classification is limited to http/https/ftp; file://,
 *    gopher://, and dict:// are classified directly as dangerous schemes.
 *  - IPv4-mapped IPv6 host matching below is a best-effort prefix check and
 *    should be verified against the actual serialized forms Node's URL
 *    parser produces before relying on it (needs test coverage).
 */

import type { Detector, DetectorContext, DetectionFinding } from './types.js';
import { adjustConfidenceForEvasion, confidenceBandFor } from './detector-utils.js';

const RULE_ID = 'input.ssrf_indicator';
const ALLOWED_SCHEMES = new Set(['http:', 'https:', 'ftp:', 'file:', 'gopher:', 'dict:']);
const DANGEROUS_SCHEMES = new Set(['file:', 'gopher:', 'dict:']);
// Cheap guard so we only attempt URL parsing on values that look like a URL
// (bounded cost; avoids throwing on arbitrary prose).
const SCHEME_LIKE = /^[a-z][a-z0-9+.-]*:\/\//iu;

const METADATA_HOSTS = new Set([
  '169.254.169.254',
  'metadata.google.internal',
  'metadata',
  'instance-data',
]);

function isPrivateOrLocalIPv4(hostname: string): boolean {
  return (
    hostname === '0.0.0.0' ||
    /^127\.(?:\d{1,3}\.){0,2}\d{1,3}$/u.test(hostname) ||
    /^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/u.test(hostname) ||
    /^192\.168\.\d{1,3}\.\d{1,3}$/u.test(hostname) ||
    /^172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}$/u.test(hostname) ||
    /^169\.254\.\d{1,3}\.\d{1,3}$/u.test(hostname)
  );
}

function isPrivateOrLocalIPv6(hostname: string): boolean {
  const stripped = hostname.replace(/^\[|\]$/gu, '');
  return (
    stripped === '::1' ||
    stripped === '::' ||
    /^fe80:/u.test(stripped) ||
    /^fc00:/u.test(stripped) ||
    /^fd00:/u.test(stripped) ||
    /^::ffff:7f/u.test(stripped) || // IPv4-mapped 127.x.x.x, hex form — verify against real test cases
    /^::ffff:127\./u.test(stripped) // IPv4-mapped 127.x.x.x, dotted form
  );
}

function hostnameReason(hostname: string): string | undefined {
  const stripped = hostname.replace(/^\[|\]$/gu, '').toLowerCase();
  if (METADATA_HOSTS.has(stripped)) return 'cloud_metadata_host';
  if (stripped === 'localhost' || stripped.endsWith('.localhost')) return 'private_or_local_host';
  if (isPrivateOrLocalIPv4(stripped)) return 'private_or_local_host';
  if (isPrivateOrLocalIPv6(hostname)) return 'private_or_local_host';
  return undefined;
}

function ssrfReason(value: string): string | undefined {
  const trimmed = value.trim();
  if (!SCHEME_LIKE.test(trimmed)) return undefined;

  let url: URL;
  try {
    url = new URL(trimmed);
  } catch {
    // Looked like a URL but failed to parse — a plausible sign of a
    // deliberately malformed value (parser-confusion bypass attempt), per
    // the original detection requirement.
    return 'malformed_url';
  }
  if (!ALLOWED_SCHEMES.has(url.protocol)) return undefined;
  if (DANGEROUS_SCHEMES.has(url.protocol)) return 'dangerous_url_scheme';
  return hostnameReason(url.hostname);
}

export const ssrfDetector: Detector = {
  ruleId: RULE_ID,
  detect(context: DetectorContext): readonly DetectionFinding[] {
    return context.values.flatMap((item) => {
      const reasonCode = ssrfReason(item.value);
      if (reasonCode === undefined) return [];
      const baseConfidence = reasonCode === 'malformed_url' ? 0.55 : 0.93;
      const confidence = adjustConfidenceForEvasion(baseConfidence, item);
      return [
        {
          ruleId: RULE_ID,
          category: 'input' as const,
          severity: reasonCode === 'malformed_url' ? ('medium' as const) : ('high' as const),
          confidence,
          confidenceBand: confidenceBandFor(confidence),
          component: item.component,
          path: item.path,
          reasonCode,
          evidenceId: `${RULE_ID}:${item.component}:${item.path}:${reasonCode}`,
        },
      ];
    });
  },
};

// src/detection/prototype-pollution.ts

/*
 * ASSUMPTION PENDING CONFIRMATION: assumes NormalizedValue.path is
 * dot-separated (e.g. "$.a.b.c", array indices as "$.items[2].x" or
 * "$.items.2.x"). Verify against the actual query/JSON path-building logic
 * before relying on this — an incorrect split means real attack payloads
 * will still pass through uncaught.
 *
 * Prototype pollution is primarily a KEY-name attack ({"__proto__": {...}}),
 * not a value match, so this checks path segments first. It also catches the
 * secondary case of a dotted-path string passed as a single value, for
 * libraries that resolve such strings dynamically (e.g. a vulnerable
 * `set(obj, "constructor.prototype.x", v)` call).
 */

import type { Detector, DetectorContext, DetectionFinding } from './types.js';
import { adjustConfidenceForEvasion, confidenceBandFor } from './detector-utils.js';

const RULE_ID = 'input.prototype_pollution_indicator';

// Case-sensitive by design: __proto__/constructor/prototype only have
// special meaning to the JS engine in their exact casing. A differently
// cased variant (__PROTO__) would not achieve real pollution, so matching
// it would be a false positive, not extra coverage.
const DANGEROUS_NAMES = new Set(['__proto__', 'constructor', 'prototype']);

function pathSegments(path: string): string[] {
  return path
    .replace(/^\$\.?/u, '')
    .split('.')
    .map((segment) => segment.replace(/\[[^\]]*\]/gu, ''))
    .filter((segment) => segment.length > 0);
}

function dangerousPathSegment(path: string): boolean {
  const segments = pathSegments(path);
  return DANGEROUS_NAMES.has(segments[segments.length - 1] ?? '');
}

// Catches a dotted chain passed as a single value, e.g.
// "constructor.prototype.polluted" — requires at least two dots so an
// ordinary single word doesn't match, and every segment must parse cleanly.
function dangerousValueChain(value: string): boolean {
  const trimmed = value.trim();
  if (!trimmed.includes('.')) return DANGEROUS_NAMES.has(trimmed);
  const segments = trimmed.split('.').filter((segment) => segment.length > 0);
  return segments.length > 1 && segments.some((segment) => DANGEROUS_NAMES.has(segment));
}

export const prototypePollutionDetector: Detector = {
  ruleId: RULE_ID,
  detect(context: DetectorContext): readonly DetectionFinding[] {
    return context.values.flatMap((item) => {
      let reasonCode: string | undefined;
      if (dangerousPathSegment(item.path)) {
        reasonCode = 'dangerous_object_property_key';
      } else if (dangerousValueChain(item.value)) {
        reasonCode = 'dangerous_object_property_value';
      }
      if (reasonCode === undefined) return [];
      const confidence = adjustConfidenceForEvasion(0.88, item);
      return [
        {
          ruleId: RULE_ID,
          category: 'input' as const,
          severity: 'high' as const,
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

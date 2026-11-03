// src/detection/open-redirect.ts

/*
 * Bounded open-redirect detector. Flags an absolute or protocol-relative
 * external URL only in a field whose path name suggests a redirect target
 * (redirect, return, next, url, uri, target, destination, callback, goto —
 * as whole words, including inside snake_case/camelCase compound names like
 * "redirect_uri" or "returnUrl"), never in unrelated fields.
 *
 * DESIGN NOTE: the path is tokenized as a single string rather than split
 * into exact segments first, because non-alphanumeric characters ($, ., [,
 * ]) already act as natural delimiters. This avoids depending on the exact
 * path-serialization format and should work whether a query param path
 * renders as "$.url" or "url".
 *
 * KNOWN TRADE-OFF: matching keywords as whole words anywhere in a compound
 * field name (not just exact-segment match) will also match some
 * semantically unrelated fields that happen to share a word, e.g.
 * "returnPolicyUrl" on an e-commerce field. This is accepted because the
 * value-shape gate (must look like an absolute/protocol-relative external
 * URL) already excludes the overwhelming majority of non-redirect field
 * values; needs a benign test case and monitor-mode telemetry review.
 */

import type { Detector, DetectorContext, DetectionFinding } from './types.js';
import { adjustConfidenceForEvasion, confidenceBandFor } from './detector-utils.js';

const RULE_ID = 'input.open_redirect_indicator';

const REDIRECT_WORDS = new Set([
  'redirect',
  'return',
  'returnto',
  'next',
  'continue',
  'url',
  'uri',
  'target',
  'destination',
  'callback',
  'goto',
]);

function pathWords(path: string): string[] {
  return path
    .replace(/([a-z0-9])([A-Z])/gu, '$1_$2') // split camelCase boundaries
    .toLowerCase()
    .split(/[^a-z0-9]+/u)
    .filter((word) => word.length > 0);
}

function isRedirectLikePath(path: string): boolean {
  return pathWords(path).some((word) => REDIRECT_WORDS.has(word));
}

// Requires >=2 consecutive slash/backslash characters in any combination,
// covering "//", "\\", "/\", "\/" — the documented backslash-as-slash
// bypass shapes — with an optional http(s): scheme prefix.
const EXTERNAL_URL = /^(?:https?:)?[\\/]{2,}[^\\/\s?#]+/iu;

export const openRedirectDetector: Detector = {
  ruleId: RULE_ID,
  detect(context: DetectorContext): readonly DetectionFinding[] {
    return context.values.flatMap((item) => {
      if (!isRedirectLikePath(item.path) || !EXTERNAL_URL.test(item.value.trim())) return [];
      const confidence = adjustConfidenceForEvasion(0.87, item);
      return [
        {
          ruleId: RULE_ID,
          category: 'input' as const,
          severity: 'medium' as const,
          confidence,
          confidenceBand: confidenceBandFor(confidence),
          component: item.component,
          path: item.path,
          reasonCode: 'external_redirect_target',
          evidenceId: `${RULE_ID}:${item.component}:${item.path}:external_redirect_target`,
        },
      ];
    });
  },
};

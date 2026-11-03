// src/detection/path-traversal.ts

import type { Detector, DetectorContext, DetectionFinding } from './types.js';
import { splitPathSegments, adjustConfidenceForEvasion, confidenceBandFor } from './detector-utils.js';

const RULE_ID = 'input.path_traversal_indicator';
const SENSITIVE_ROOT_SEGMENTS = new Set([
  'etc',
  'proc',
  'windows',
  'winnt',
  'system32',
  'syswow64',
]);

export const pathTraversalDetector: Detector = {
  ruleId: RULE_ID,
  detect(context: DetectorContext): readonly DetectionFinding[] {
    return context.values.flatMap((item) => {
      const trimmed = item.value.trim();
      const segments = splitPathSegments(item.value);
      const hasParent = segments.includes('..');
      // A sensitive name only means something as the ROOT of an absolute
      // path (/etc/passwd, /proc/self, \windows\system32) — not as any
      // nested segment of an app's own route (/files/etc) or a bare word.
      const isAbsolute = /^([\\/]|[a-z]:[\\/])/u.test(trimmed);
      const rootIndex = /^[a-z]:[\\/]/u.test(trimmed) ? 1 : 0;
      const hasSensitiveRoot =
        isAbsolute &&
        SENSITIVE_ROOT_SEGMENTS.has((segments[rootIndex] ?? '').replace(/:$/u, ''));
      if (!hasParent && !hasSensitiveRoot) return [];
      const reasonCode = hasParent ? 'parent_path_segment' : 'sensitive_system_path_segment';
      const confidence = adjustConfidenceForEvasion(hasParent ? 0.94 : 0.9, item);
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
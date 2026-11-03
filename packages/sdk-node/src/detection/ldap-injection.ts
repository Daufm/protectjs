import type { Detector, DetectorContext, DetectionFinding } from './types.js';
import { adjustConfidenceForEvasion, confidenceBandFor } from './detector-utils.js';

const RULE_ID = 'input.ldap_injection_indicator';
const FILTER_INJECTION = /\)\s*\(\s*(?:uid|cn|objectclass|userpassword)\s*=/iu;
const WILDCARD_FILTER = /\*\s*\)\s*\(/u;

function ldapInjectionReason(value: string): string | undefined {
  if (FILTER_INJECTION.test(value)) return 'ldap_filter_clause';
  if (WILDCARD_FILTER.test(value) && value.includes('(') && value.includes('=')) {
    return 'ldap_wildcard_filter';
  }
  return undefined;
}

export const ldapInjectionDetector: Detector = {
  ruleId: RULE_ID,
  detect(context: DetectorContext): readonly DetectionFinding[] {
    return context.values.flatMap((item) => {
      const reasonCode = ldapInjectionReason(item.value);
      if (reasonCode === undefined) return [];
      const confidence = adjustConfidenceForEvasion(0.85, item);
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

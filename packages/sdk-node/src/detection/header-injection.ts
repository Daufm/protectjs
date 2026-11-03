import type { Detector, DetectorContext, DetectionFinding } from './types.js';
import { adjustConfidenceForEvasion, confidenceBandFor } from './detector-utils.js';

const RULE_ID = 'input.header_injection_indicator';
const CRLF_HEADER = /\r\n[\t ]*[\w-]{1,64}\s*:/u;

export const headerInjectionDetector: Detector = {
  ruleId: RULE_ID,
  detect(context: DetectorContext): readonly DetectionFinding[] {
    return context.values.flatMap((item) => {
      if (!CRLF_HEADER.test(item.value)) return [];
      const confidence = adjustConfidenceForEvasion(0.9, item);
      return [
        {
          ruleId: RULE_ID,
          category: 'input' as const,
          severity: 'high' as const,
          confidence,
          confidenceBand: confidenceBandFor(confidence),
          component: item.component,
          path: item.path,
          reasonCode: 'crlf_header_injection',
          evidenceId: `${RULE_ID}:${item.component}:${item.path}:crlf_header_injection`,
        },
      ];
    });
  },
};

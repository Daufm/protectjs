import type { Detector, DetectorContext, DetectionFinding } from './types.js';
import { adjustConfidenceForEvasion, confidenceBandFor } from './detector-utils.js';

const RULE_ID = 'input.xxe_indicator';

function isXxeIndicator(value: string): boolean {
  return /<!doctype/iu.test(value) && /<!entity/iu.test(value) && /\bsystem\b/iu.test(value);
}

export const xxeDetector: Detector = {
  ruleId: RULE_ID,
  detect(context: DetectorContext): readonly DetectionFinding[] {
    return context.values.flatMap((item) => {
      if (!isXxeIndicator(item.value)) return [];
      const confidence = adjustConfidenceForEvasion(0.91, item);
      return [
        {
          ruleId: RULE_ID,
          category: 'input' as const,
          severity: 'high' as const,
          confidence,
          confidenceBand: confidenceBandFor(confidence),
          component: item.component,
          path: item.path,
          reasonCode: 'xml_external_entity',
          evidenceId: `${RULE_ID}:${item.component}:${item.path}:xml_external_entity`,
        },
      ];
    });
  },
};

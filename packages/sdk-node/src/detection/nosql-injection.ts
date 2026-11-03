// src/detection/nosql-injection.ts

import type { Detector, DetectorContext, DetectionFinding } from './types.js';
import {
  parseNoSqlOperator,
  adjustConfidenceForEvasion,
  confidenceBandFor,
} from './detector-utils.js';

const RULE_ID = 'input.nosql_injection_indicator';

export const nosqlInjectionDetector: Detector = {
  ruleId: RULE_ID,
  detect(context: DetectorContext): readonly DetectionFinding[] {
    return context.values.flatMap((item) => {
      const operator = parseNoSqlOperator(item.value);
      if (operator === undefined) return [];
      const reasonCode =
        operator === '$where' ||
        operator === '$expr' ||
        operator === '$function' ||
        operator === '$code'
          ? 'nosql_script_operator'
          : 'nosql_query_operator';
      const confidence = adjustConfidenceForEvasion(
        reasonCode === 'nosql_script_operator' ? 0.9 : 0.84,
        item,
      );
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

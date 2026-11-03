import type { Detector, DetectorContext, DetectionFinding } from './types.js';
import { adjustConfidenceForEvasion, confidenceBandFor } from './detector-utils.js';

const RULE_ID = 'input.template_injection_indicator';

const JNDI = /\$\{jndi:/iu;
const EXPRESSION =
  /\{\{[^}]{0,80}(?:__|\bconfig\b|\bself\b|\brequest\b|\b7\s*\*\s*7)[^}]{0,80}\}\}/iu;

function templateInjectionReason(value: string): string | undefined {
  if (JNDI.test(value)) return 'jndi_lookup_expression';
  if (EXPRESSION.test(value)) return 'template_expression';
  return undefined;
}

export const templateInjectionDetector: Detector = {
  ruleId: RULE_ID,
  detect(context: DetectorContext): readonly DetectionFinding[] {
    return context.values.flatMap((item) => {
      const reasonCode = templateInjectionReason(item.value);
      if (reasonCode === undefined) return [];
      const confidence = adjustConfidenceForEvasion(
        reasonCode === 'jndi_lookup_expression' ? 0.95 : 0.84,
        item,
      );
      return [
        {
          ruleId: RULE_ID,
          category: 'input' as const,
          severity:
            reasonCode === 'jndi_lookup_expression' ? ('critical' as const) : ('high' as const),
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

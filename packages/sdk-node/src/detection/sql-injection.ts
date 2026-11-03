// src/detection/sql-injection.ts

import type { Detector, DetectorContext, DetectionFinding } from './types.js';
import { parseSqlInput, adjustConfidenceForEvasion, confidenceBandFor } from './detector-utils.js';

const RULE_ID = 'input.sql_injection_indicator';
const KEYWORDS = new Set([
  'union',
  'select',
  'from',
  'insert',
  'into',
  'update',
  'set',
  'delete',
  'drop',
  'table',
  'database',
  'sleep',
  'benchmark',
  'waitfor',
  'delay',
  'pg_sleep',
  'dbms_pipe',
  'load_file',
  'outfile',
  'dumpfile',
  'xp_cmdshell',
  'or',
  'and',
  'true',
  'false',
]);

function hasSequence(words: readonly string[], first: string, second: string): boolean {
  return words.some((word, index) => word === first && words[index + 1] === second);
}

function isSqlIndicator(value: string): string | undefined {
  const parsed = parseSqlInput(value);
  const words = parsed.tokens;
  if (words.some((word) => !KEYWORDS.has(word) && word.length > 128)) return undefined;

  if (/['"]\s*(?:or|and)\s*['"][^'"]*['"]\s*=\s*['"]/iu.test(value)) {
    return 'sql_boolean_expression';
  }
  if (
    words.includes('xp_cmdshell') ||
    (words.includes('load_file') && parsed.hasCallSyntax) ||
    (words.includes('outfile') && parsed.hasSyntaxMarker) ||
    (words.includes('dumpfile') && parsed.hasSyntaxMarker)
  ) {
    return 'sql_dangerous_function';
  }

  const keywordSequence =
    hasSequence(words, 'union', 'select') ||
    hasSequence(words, 'select', 'from') ||
    hasSequence(words, 'insert', 'into') ||
    hasSequence(words, 'update', 'set') ||
    hasSequence(words, 'delete', 'from') ||
    hasSequence(words, 'drop', 'table') ||
    hasSequence(words, 'drop', 'database');

  // UNION SELECT is an unambiguous injection shape even without punctuation.
  // Other keyword pairs need a syntax marker to avoid classifying phrases
  // such as "delete from cart" or "select from the list".
  if (
    hasSequence(words, 'union', 'select') ||
    /\bunion\s*(?:\/\*[\s\S]*?\*\/\s*)?select\b/iu.test(value) ||
    (keywordSequence && parsed.hasSyntaxMarker)
  ) {
    return 'sql_keyword_sequence';
  }
  if ((words.includes('or') || words.includes('and')) && parsed.hasQuotedEquality) {
    return 'sql_boolean_expression';
  }
  if (
    ((words.includes('sleep') || words.includes('benchmark') || words.includes('pg_sleep')) &&
      parsed.hasCallSyntax) ||
    hasSequence(words, 'waitfor', 'delay')
  ) {
    return 'sql_timing_function';
  }
  return undefined;
}

export const sqlInjectionDetector: Detector = {
  ruleId: RULE_ID,
  detect(context: DetectorContext): readonly DetectionFinding[] {
    return context.values.flatMap((item) => {
      const reasonCode = isSqlIndicator(item.value);
      if (reasonCode === undefined) return [];
      const confidence = adjustConfidenceForEvasion(0.86, item);
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

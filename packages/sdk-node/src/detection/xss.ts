// src/detection/xss.ts

import type { Detector, DetectorContext, DetectionFinding } from './types.js';
import { parseHtmlInput, adjustConfidenceForEvasion, confidenceBandFor } from './detector-utils.js';

const RULE_ID = 'input.xss_indicator';
const DANGEROUS_TAGS = new Set([
  'svg',
  'img',
  'iframe',
  'object',
  'embed',
  'frame',
  'frameset',
  'meta',
  'base',
  'link',
  'form',
]);

function decodeHtmlEntities(value: string): string {
  return value.replace(/&(?:#x[0-9a-f]+|#\d+|lt|gt|quot|apos|amp);/giu, (entity) => {
    const lower = entity.toLowerCase();
    if (lower === '&lt;') return '<';
    if (lower === '&gt;') return '>';
    if (lower === '&quot;') return '"';
    if (lower === '&apos;') return "'";
    if (lower === '&amp;') return '&';
    if (lower.startsWith('&#x')) {
      const code = Number.parseInt(lower.slice(3, -1), 16);
      return Number.isFinite(code) && code >= 32 && code < 0xd800
        ? String.fromCodePoint(code)
        : entity;
    }
    const code = Number.parseInt(lower.slice(2, -1), 10);
    return Number.isFinite(code) && code >= 32 && code < 0xd800
      ? String.fromCodePoint(code)
      : entity;
  });
}

function reasonFromParsed(value: string): string | undefined {
  const parsed = parseHtmlInput(value);
  if (parsed.scheme === 'javascript') return 'javascript_scheme';
  if (parsed.scheme === 'vbscript') return 'vbscript_scheme';
  if (parsed.scheme === 'data-html') return 'html_data_scheme';
  if (parsed.scheme === 'data-script') return 'javascript_data_scheme';
  for (const tag of parsed.tags) {
    if (tag.name === 'script') return 'script_element';
    if (tag.executableAttribute) return 'executable_markup_attribute';
    if (DANGEROUS_TAGS.has(tag.name)) return 'dangerous_markup_element';
  }
  return undefined;
}

function xssReason(value: string): string | undefined {
  return reasonFromParsed(value) ?? reasonFromParsed(decodeHtmlEntities(value));
}

export const xssDetector: Detector = {
  ruleId: RULE_ID,
  detect(context: DetectorContext): readonly DetectionFinding[] {
    return context.values.flatMap((item) => {
      const reasonCode = xssReason(item.value);
      if (reasonCode === undefined) return [];
      const confidence = adjustConfidenceForEvasion(0.82, item);
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

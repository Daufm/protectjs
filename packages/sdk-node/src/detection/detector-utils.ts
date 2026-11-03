// src/detection/detector-utils.ts

import type {
  DetectionFinding,
  DetectorContext,
  InspectedComponent,
  NormalizedValue,
} from './types.js';

const MAX_TOKENS = 256;
const MAX_TOKEN_LENGTH = 128;

export interface StructuredSqlInput {
  readonly tokens: readonly string[];
  readonly hasQuotedEquality: boolean;
  readonly hasCallSyntax: boolean;
  /** True when the value contains an actual SQL syntax marker (quote, block
   * or line comment, semicolon, or call parenthesis) rather than just
   * English words that happen to match keyword names. */
  readonly hasSyntaxMarker: boolean;
}

export function parseSqlInput(value: string): StructuredSqlInput {
  const tokens: string[] = [];
  let token = '';
  let quote: '"' | "'" | undefined;
  let hasQuotedEquality = false;
  let hasCallSyntax = false;
  let hasSyntaxMarker = false;

  const pushToken = (): void => {
    if (token.length > 0 && tokens.length < MAX_TOKENS) {
      tokens.push(token.slice(0, MAX_TOKEN_LENGTH));
    }
    token = '';
  };

  for (let index = 0; index < value.length && tokens.length < MAX_TOKENS; index += 1) {
    const character = value[index] ?? '';
    const next = value[index + 1] ?? '';
    if (quote !== undefined) {
      if (character === '\\') {
        index += 1;
        continue;
      }
      if (character === quote) quote = undefined;
      continue;
    }
    if (character === "'" || character === '"') {
      pushToken(); // flush pending token before entering quoted content
      quote = character;
      hasSyntaxMarker = true;
      continue;
    }
    if (character === '/' && next === '*') {
      hasSyntaxMarker = true;
      const end = value.indexOf('*/', index + 2);
      index = end < 0 ? value.length : end + 1;
      continue;
    }
    if (character === '-' && next === '-') {
      pushToken();
      hasSyntaxMarker = true;
      const end = value.indexOf('\n', index + 2);
      index = end < 0 ? value.length : end;
      continue;
    }
    if (character === '#') {
      pushToken();
      hasSyntaxMarker = true;
      const end = value.indexOf('\n', index + 1);
      index = end < 0 ? value.length : end;
      continue;
    }
    if (character === ';') hasSyntaxMarker = true;
    if (character === '(') hasCallSyntax = true;
    if (character === '=' && tokens.length > 0) {
      hasQuotedEquality = /['"][^'"]*['"]?\s*=\s*['"]?[^'"]+/u.test(value);
    }
    if (/[a-z0-9_$]/iu.test(character)) token += character.toLowerCase();
    else pushToken();
  }
  pushToken();
  return {
    tokens,
    hasQuotedEquality,
    hasCallSyntax,
    hasSyntaxMarker: hasSyntaxMarker || hasCallSyntax,
  };
}

export interface StructuredHtmlInput {
  readonly scheme: 'javascript' | 'vbscript' | 'data-html' | 'data-script' | undefined;
  readonly schemeContext: 'value' | 'attribute' | undefined;
  readonly tags: readonly { readonly name: string; readonly executableAttribute: boolean }[];
}

function classifyScheme(candidate: string): StructuredHtmlInput['scheme'] | undefined {
  if (/^javascript:\S/iu.test(candidate)) return 'javascript';
  if (/^vbscript:\S/iu.test(candidate)) return 'vbscript';
  if (/^data:text\/html[,;]/iu.test(candidate)) return 'data-html';
  if (/^data:(?:text|application)\/(?:javascript|ecmascript)[,;]/iu.test(candidate)) {
    return 'data-script';
  }
  return undefined;
}

function classifyAttrScheme(candidate: string): StructuredHtmlInput['scheme'] | undefined {
  if (/^(javascript|vbscript):/iu.test(candidate)) {
    return /^vbscript:/iu.test(candidate) ? 'vbscript' : 'javascript';
  }
  if (/^data:text\/html[,;]/iu.test(candidate)) return 'data-html';
  if (/^data:(?:text|application)\/(?:javascript|ecmascript)[,;]/iu.test(candidate)) {
    return 'data-script';
  }
  return undefined;
}

const URI_ATTR_PATTERN = /\b(?:href|src|action|formaction)\s*=\s*(["'])([\s\S]*?)\1/giu;

export function parseHtmlInput(value: string): StructuredHtmlInput {
  const trimmed = value.trim();
  let scheme: StructuredHtmlInput['scheme'] = classifyScheme(trimmed);
  let schemeContext: StructuredHtmlInput['schemeContext'] =
    scheme === undefined ? undefined : 'value';

  const tags: { name: string; executableAttribute: boolean }[] = [];
  const tagPattern = /<\s*([a-z][a-z0-9-]*)\b([^>]*)>/giu;
  let match: RegExpExecArray | null;
  while ((match = tagPattern.exec(value)) !== null && tags.length < MAX_TOKENS) {
    const name = (match[1] ?? '').toLowerCase();
    const attributes = match[2] ?? '';
    tags.push({
      name,
      executableAttribute:
        /\bon[a-z][a-z0-9-]*\s*=/iu.test(attributes) || /\bsrcdoc\s*=/iu.test(attributes),
    });

    if (scheme === undefined) {
      URI_ATTR_PATTERN.lastIndex = 0;
      let attrMatch: RegExpExecArray | null;
      while ((attrMatch = URI_ATTR_PATTERN.exec(attributes)) !== null) {
        const attrValue = (attrMatch[2] ?? '').trim();
        const attrScheme = classifyAttrScheme(attrValue);
        if (attrScheme !== undefined) {
          scheme = attrScheme;
          schemeContext = 'attribute';
          break;
        }
      }
    }
  }

  return { scheme, schemeContext, tags };
}

export function splitPathSegments(value: string): readonly string[] {
  return value
    .split(/[\\/]+/u)
    .map((segment) => segment.trim())
    .filter((segment) => segment.length > 0)
    .slice(0, MAX_TOKENS);
}

const NOSQL_OPERATORS = new Set([
  '$where',
  '$ne',
  '$gt',
  '$gte',
  '$lt',
  '$lte',
  '$in',
  '$nin',
  '$regex',
  '$expr',
  '$or',
  '$and',
  '$nor',
  '$not',
  '$function',
  '$text',
  '$elemmatch',
  '$lookup',
  '$jsonschema',
  '$code',
]);

export function parseNoSqlOperator(value: string): string | undefined {
  const operator = /^\$[a-z][a-z0-9]*/u.exec(value.trim())?.[0];
  return operator !== undefined && NOSQL_OPERATORS.has(operator) ? operator : undefined;
}

export function confidenceBandFor(confidence: number): 'low' | 'medium' | 'high' {
  return confidence >= 0.85 ? 'high' : confidence >= 0.6 ? 'medium' : 'low';
}

/**
 * Nudges a detector's base confidence using evidence the engine already
 * collects during normalization but that detectors previously ignored:
 * decode depth, transformation count, ambiguity and truncation. A value that
 * needed two rounds of percent-decoding to reveal a payload is more likely
 * deliberate evasion than one that matched in its raw form.
 */
export function adjustConfidenceForEvasion(base: number, value: NormalizedValue): number {
  let confidence = base;
  if (value.decodeDepth > 1) confidence += 0.04;
  if (value.transformations.length > 1) confidence += 0.03;
  if (value.ambiguous) confidence += 0.03;
  if (value.duplicateStatus === 'present') confidence += 0.02;
  if (value.truncated) confidence -= 0.06; // signal may be incomplete
  return Math.round(Math.min(0.99, Math.max(0.05, confidence)) * 100) / 100;
}

export function findMatches(
  context: DetectorContext,
  component: InspectedComponent,
  pattern: RegExp,
  ruleId: string,
  category: DetectionFinding['category'],
  severity: DetectionFinding['severity'],
  confidence: number,
  reasonCode: string,
): DetectionFinding[] {
  const findings: DetectionFinding[] = [];
  for (const value of context.values) {
    if (value.component !== component || !pattern.test(value.value)) continue;
    findings.push({
      ruleId,
      category,
      severity,
      confidence,
      confidenceBand: confidenceBandFor(confidence),
      component: value.component,
      path: value.path,
      reasonCode,
      evidenceId: `${ruleId}:${value.component}:${value.path}:${reasonCode}`,
    });
  }
  return findings;
}

export function findMatchesAcrossComponents(
  context: DetectorContext,
  pattern: RegExp,
  ruleId: string,
  category: DetectionFinding['category'],
  severity: DetectionFinding['severity'],
  confidence: number,
  reasonCode: string,
): DetectionFinding[] {
  const findings: DetectionFinding[] = [];
  for (const value of context.values) {
    if (!pattern.test(value.value)) continue;
    findings.push({
      ruleId,
      category,
      severity,
      confidence,
      confidenceBand: confidenceBandFor(confidence),
      component: value.component,
      path: value.path,
      reasonCode,
      evidenceId: `${ruleId}:${value.component}:${value.path}:${reasonCode}`,
    });
  }
  return findings;
}

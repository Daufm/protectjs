import type {
  HttpMethod,
  SecurityDecision,
  SecurityEvent,
  SecurityPolicy,
} from '@ethioshield/security-contracts';
import {
  assertSecurityEvent,
  assertSecurityPolicy,
  CURRENT_SCHEMA_VERSION,
  isHttpMethod,
} from '@ethioshield/security-contracts';
import { DetectionEngine } from './detection/engine.js';
import { evaluateDetection } from './detection/policy-evaluator.js';
import type { DetectionRequest, DetectionResult } from './detection/types.js';
import { sanitizeEventRoute } from './event-route.js';
import { SDK_VERSION } from './version.js';

export interface RequestInput {
  readonly method: HttpMethod;
  readonly path: string;
  readonly query?: unknown;
  readonly routeParams?: unknown;
  readonly body?: unknown;
  readonly headers?: unknown;
}

export interface EvaluationResult {
  readonly decision: SecurityDecision;
  readonly event: SecurityEvent;
  readonly detection: DetectionResult;
}

export interface EvaluateRequestOptions {
  readonly projectId: string;
  readonly policy: SecurityPolicy;
  readonly request: RequestInput;
  readonly engine?: DetectionEngine;
  readonly clock?: () => Date;
  readonly eventId?: () => string;
}

function toDetectionRequest(request: RequestInput): DetectionRequest {
  return {
    method: request.method,
    route: request.path,
    ...(request.query === undefined ? {} : { query: request.query }),
    ...(request.routeParams === undefined ? {} : { routeParams: request.routeParams }),
    ...(request.body === undefined ? {} : { body: request.body }),
    ...(request.headers === undefined ? {} : { headers: request.headers }),
  };
}

export function evaluateRequest(options: EvaluateRequestOptions): EvaluationResult {
  assertSecurityPolicy(options.policy);
  if (!isHttpMethod(options.request.method)) {
    throw new TypeError('Unsupported request method');
  }
  const engine = options.engine ?? new DetectionEngine();
  const clock = options.clock ?? (() => new Date());
  const eventId = options.eventId ?? (() => crypto.randomUUID());
  const detection = engine.inspect(toDetectionRequest(options.request));
  const evaluation = evaluateDetection(options.policy, detection, {
    enforcementMode: options.policy.enforcementMode,
    fallbackAction: options.policy.defaults.action,
  });
  const decision: SecurityDecision = {
    action: evaluation.action,
    ruleId: evaluation.ruleId,
    category: evaluation.category,
    severity: evaluation.finding?.severity ?? options.policy.defaults.severity,
    policyVersion: options.policy.policyVersion,
    reason: {
      code: evaluation.reasonCode,
      attributes: {
        findingCount: detection.findings.length,
      },
    },
    ...(evaluation.finding === undefined ? {} : { confidence: evaluation.finding.confidence }),
  };
  const event: SecurityEvent = {
    schemaVersion: CURRENT_SCHEMA_VERSION,
    eventId: eventId(),
    projectId: options.projectId,
    occurredAt: clock().toISOString(),
    request: {
      method: options.request.method,
      route: sanitizeEventRoute(options.request.path),
    },
    detection: {
      category: evaluation.finding?.category ?? decision.category,
      ruleId: evaluation.finding?.ruleId ?? decision.ruleId,
    },
    decision,
    sdkVersion: SDK_VERSION,
  };
  assertSecurityEvent(event);
  return { decision, event, detection };
}

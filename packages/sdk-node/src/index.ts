import { EthioShieldExpressMiddleware } from './express.js';
import type { EthioShieldExpressOptions } from './express.js';
import { evaluateRequest } from './inspect.js';
import type { RequestInput } from './inspect.js';
export { SDK_VERSION } from './version.js';
export { evaluateRequest } from './inspect.js';
export type { EvaluationResult, RequestInput, EvaluateRequestOptions } from './inspect.js';
export { DetectionEngine, defaultDetectors } from './detection/engine.js';
export type {
  DetectionContext,
  DetectionBudgetOutcome,
  BodyInspectionState,
  DetectionError,
  DetectionFinding,
  DetectionPlugin,
  DetectionRequest,
  DetectionResult,
  DetectionOutcome,
} from './detection/types.js';
export type {
  DetectionInspectionErrorCode,
  DetectionInspectionStatus,
} from '@ethioshield/security-contracts';
export type { Detector } from './detection/types.js';
export { asDetectionPlugin, isDetectionPlugin } from './detection/plugin.js';
export { evaluateDetection } from './detection/policy-evaluator.js';
export type { PolicyEvaluation } from './detection/policy-evaluator.js';
export {
  headersParser,
  jsonParser,
  queryParser,
  routeParamsParser,
} from './detection/parsers/index.js';
export type {
  ParsedComponent,
  ParserAdapter,
  ParserError,
  ParserResult,
  SanitizedHeaders,
} from './detection/parsers/index.js';
export { LayeredRateLimiter } from './rate-limit/limiter.js';
export { InMemoryAtomicCounterStore } from './rate-limit/store.js';
export { RedisAtomicCounterStore } from './rate-limit/redis-store.js';
export type { RedisEval, RedisAtomicCounterStoreOptions } from './rate-limit/redis-store.js';
export type {
  AtomicCounterStore,
  RateLimitIdentity,
  RateLimitOptions,
  RateLimitOutcome,
  RateLimitRequest,
} from './rate-limit/types.js';
export type { RateLimitConfiguration } from './express.js';
export { resolveNetworkRisk } from './network-intelligence.js';
export type { NetworkIntelligenceResolver } from './network-intelligence.js';
export { InstrumentationHub } from './instrumentation.js';
export type {
  AuthorizationObservation,
  CommandObservation,
  FilesystemObservation,
  InstrumentationFailure,
  InstrumentationObservers,
  InstrumentationOptions,
  InstrumentationResult,
  OutboundHttpObservation,
  SqlObservation,
} from './instrumentation.js';
export { correlateSinkObservation } from './detection/sink-correlation.js';
export type {
  CorrelatedFinding,
  ExploitabilityStatus,
  SinkCorrelationResult,
  SinkKind,
  SinkObservation,
} from './detection/sink-correlation.js';
export { InMemoryCorrelationStore, StatefulCorrelator } from './correlation.js';
export type {
  CorrelationOptions,
  CorrelationOutcome,
  CorrelationRequest,
  CorrelationStore,
} from './correlation.js';
export type { ChallengeAdapter } from './challenge.js';
export { EthioShieldExpressMiddleware, createEthioShieldExpress } from './express.js';
export { sanitizeEventRoute } from './event-route.js';
export type {
  DecisionContext,
  EnforcementMode,
  EthioShieldExpress,
  EthioShieldExpressOptions,
  CorrelationConfiguration,
  InspectionConfiguration,
  TelemetryAdapter,
  TrustedProxyConfiguration,
} from './express.js';

export type EthioShieldOptions = EthioShieldExpressOptions;

export class EthioShield extends EthioShieldExpressMiddleware {
  public constructor(options: EthioShieldOptions) {
    super(options);
  }

  public evaluate(request: RequestInput) {
    return evaluateRequest({
      projectId: this.options.projectId,
      policy: this.options.policy,
      request,
      engine: this.options.engine,
      clock: this.options.clock,
      eventId: this.options.eventId,
    });
  }
}

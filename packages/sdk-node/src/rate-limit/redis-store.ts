import type { AtomicCounterStore, CounterResult } from './types.js';
import { MAX_COUNTER_KEYS } from './types.js';

const INCREMENT_SCRIPT = `
local count = redis.call('INCR', KEYS[1])
if count == 1 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
end
local ttl = redis.call('PTTL', KEYS[1])
return {count, ttl}
`;

export type RedisEval = (
  script: string,
  keys: readonly string[],
  args: readonly string[],
) => Promise<unknown>;

export interface RedisAtomicCounterStoreOptions {
  readonly eval: RedisEval;
  readonly keyPrefix?: string;
  readonly maxKeys?: number;
}

function asInteger(value: unknown): number | undefined {
  if (typeof value === 'number' && Number.isFinite(value)) return Math.trunc(value);
  if (typeof value === 'string' && /^-?\d+$/u.test(value)) return Number.parseInt(value, 10);
  if (typeof value === 'bigint') return Number(value);
  return undefined;
}

export class RedisAtomicCounterStore implements AtomicCounterStore {
  private readonly evalScript: RedisEval;
  private readonly keyPrefix: string;

  public constructor(options: RedisAtomicCounterStoreOptions) {
    if (options.maxKeys !== undefined) {
      if (
        !Number.isInteger(options.maxKeys) ||
        options.maxKeys < 1 ||
        options.maxKeys > MAX_COUNTER_KEYS
      ) {
        throw new TypeError(`maxKeys must be an integer between 1 and ${MAX_COUNTER_KEYS}`);
      }
    }
    this.evalScript = options.eval;
    this.keyPrefix = options.keyPrefix ?? 'ethioshield:rl:';
  }

  public async increment(key: string, windowSeconds: number, now: number): Promise<CounterResult> {
    const result = await this.evalScript(INCREMENT_SCRIPT, [`${this.keyPrefix}${key}`], [
      String(windowSeconds * 1_000),
    ]);
    const pair = Array.isArray(result) ? result : undefined;
    const count = asInteger(pair?.[0]);
    const ttl = asInteger(pair?.[1]);
    if (count === undefined || count < 1) {
      throw new Error('redis counter returned an invalid count');
    }
    const resetAt = ttl !== undefined && ttl > 0 ? now + ttl : now + windowSeconds * 1_000;
    return { count, resetAt, limit: Number.MAX_SAFE_INTEGER };
  }
}

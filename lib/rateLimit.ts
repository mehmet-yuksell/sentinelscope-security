import { Redis } from "@upstash/redis";
import { errorFields, logger } from "@/lib/logger";

const DEFAULT_MAX_TRACKED_KEYS = 10_000;

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  retryAfterMs: number;
}

export interface RateLimiterLike {
  check(key: string): Promise<RateLimitResult>;
}

interface Bucket {
  count: number;
  windowStart: number;
}

/**
 * In-memory fixed-window rate limiter keyed by client IP. Correct for a
 * single long-running process (local dev, Docker, a VPS) — but each
 * serverless instance on a platform like Vercel gets its own memory, so
 * limits aren't actually shared. Use RedisRateLimiter there instead.
 *
 * Bounded: when maxTrackedKeys is reached, buckets whose window has ended are
 * swept, and if that isn't enough the oldest bucket is dropped.
 */
export class MemoryRateLimiter implements RateLimiterLike {
  private buckets = new Map<string, Bucket>();

  constructor(
    private readonly max: number,
    private readonly windowMs: number,
    private readonly maxTrackedKeys: number = DEFAULT_MAX_TRACKED_KEYS
  ) {}

  get trackedKeys(): number {
    return this.buckets.size;
  }

  async check(key: string): Promise<RateLimitResult> {
    const now = Date.now();
    const bucket = this.buckets.get(key);

    if (!bucket || now - bucket.windowStart >= this.windowMs) {
      this.buckets.delete(key);
      if (this.buckets.size >= this.maxTrackedKeys) this.makeRoom(now);
      this.buckets.set(key, { count: 1, windowStart: now });
      return { allowed: true, remaining: this.max - 1, retryAfterMs: 0 };
    }

    if (bucket.count >= this.max) {
      return { allowed: false, remaining: 0, retryAfterMs: this.windowMs - (now - bucket.windowStart) };
    }

    bucket.count += 1;
    return { allowed: true, remaining: this.max - bucket.count, retryAfterMs: 0 };
  }

  private makeRoom(now: number): void {
    for (const [key, bucket] of this.buckets) {
      if (now - bucket.windowStart >= this.windowMs) this.buckets.delete(key);
    }
    if (this.buckets.size >= this.maxTrackedKeys) {
      const oldest = this.buckets.keys().next().value;
      if (oldest !== undefined) this.buckets.delete(oldest);
    }
  }
}

/**
 * Uses `primary` (Redis) and, if it throws — an outage, a bad token, a
 * network error — falls back to a per-instance `fallback` limiter instead of
 * failing every analyze request with a 500. Limits are then only enforced per
 * instance until Redis recovers, which is logged.
 */
export class FallbackRateLimiter implements RateLimiterLike {
  constructor(
    private readonly primary: RateLimiterLike,
    private readonly fallback: RateLimiterLike
  ) {}

  async check(key: string): Promise<RateLimitResult> {
    try {
      return await this.primary.check(key);
    } catch (err) {
      logger.warn("rate_limiter.fallback", errorFields(err));
      return this.fallback.check(key);
    }
  }
}

/**
 * Redis-backed fixed-window rate limiter (via Upstash's REST API) shared
 * across every serverless instance — required for the limit to mean
 * anything once the app runs as multiple stateless functions.
 */
export class RedisRateLimiter implements RateLimiterLike {
  private redis: Redis;

  constructor(
    url: string,
    token: string,
    private readonly max: number,
    private readonly windowMs: number
  ) {
    this.redis = new Redis({ url, token });
  }

  async check(key: string): Promise<RateLimitResult> {
    const bucketId = Math.floor(Date.now() / this.windowMs);
    const redisKey = `sentinelscope:ratelimit:${key}:${bucketId}`;

    const count = await this.redis.incr(redisKey);
    if (count === 1) {
      await this.redis.pexpire(redisKey, this.windowMs);
    }

    if (count > this.max) {
      const ttl = await this.redis.pttl(redisKey);
      return { allowed: false, remaining: 0, retryAfterMs: ttl > 0 ? ttl : this.windowMs };
    }

    return { allowed: true, remaining: this.max - count, retryAfterMs: 0 };
  }
}

export function getClientIp(headers: Headers): string {
  const forwardedFor = headers.get("x-forwarded-for");
  if (forwardedFor) return forwardedFor.split(",")[0]!.trim();
  return headers.get("x-real-ip") ?? "unknown";
}

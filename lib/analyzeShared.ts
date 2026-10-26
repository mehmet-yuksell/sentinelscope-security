import { TtlCache } from "@/lib/cache";
import { FallbackRateLimiter, MemoryRateLimiter, RedisRateLimiter, type RateLimiterLike } from "@/lib/rateLimit";
import { getRedisCredentials } from "@/lib/redisConfig";
import type { AnalysisResult } from "@/types/analysis";

const RATE_LIMIT_MAX = Number(process.env.RATE_LIMIT_MAX ?? 10);
const RATE_LIMIT_WINDOW_MS = Number(process.env.RATE_LIMIT_WINDOW_MS ?? 60_000);
const CACHE_TTL_MS = Number(process.env.ANALYSIS_CACHE_TTL_MS ?? 300_000);

/**
 * Picks Redis-backed rate limiting when Upstash credentials are configured
 * (required for the limit to hold across serverless instances, e.g. on
 * Vercel), with an in-memory fallback if Redis is unreachable; otherwise an
 * in-memory limiter for a single long-running process.
 */
function createRateLimiter(): RateLimiterLike {
  const memory = new MemoryRateLimiter(RATE_LIMIT_MAX, RATE_LIMIT_WINDOW_MS);
  const redis = getRedisCredentials();
  if (!redis) return memory;
  return new FallbackRateLimiter(new RedisRateLimiter(redis.url, redis.token, RATE_LIMIT_MAX, RATE_LIMIT_WINDOW_MS), memory);
}

/**
 * Shared across both /api/analyze and /api/analyze/stream so a client can't
 * bypass the rate limit or cache by switching endpoints.
 */
export const rateLimiter = createRateLimiter();
export const resultCache = new TtlCache<AnalysisResult>(CACHE_TTL_MS);

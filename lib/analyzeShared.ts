import { TtlCache } from "@/lib/cache";
import { RateLimiter } from "@/lib/rateLimit";
import type { AnalysisResult } from "@/types/analysis";

const RATE_LIMIT_MAX = Number(process.env.RATE_LIMIT_MAX ?? 10);
const RATE_LIMIT_WINDOW_MS = Number(process.env.RATE_LIMIT_WINDOW_MS ?? 60_000);
const CACHE_TTL_MS = Number(process.env.ANALYSIS_CACHE_TTL_MS ?? 300_000);

/**
 * Shared across both /api/analyze and /api/analyze/stream so a client can't
 * bypass the rate limit or cache by switching endpoints.
 */
export const rateLimiter = new RateLimiter(RATE_LIMIT_MAX, RATE_LIMIT_WINDOW_MS);
export const resultCache = new TtlCache<AnalysisResult>(CACHE_TTL_MS);

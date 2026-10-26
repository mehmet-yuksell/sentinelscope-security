import { z } from "zod";
import { rateLimiter } from "@/lib/analyzeShared";
import { errorFields, logger } from "@/lib/logger";
import { getClientIp } from "@/lib/rateLimit";
import { SsrfBlockedError } from "@/lib/security/ssrf";
import { saveAnalysis } from "@/lib/store";
import { InvalidTargetError } from "@/lib/validation/target";
import type { AnalysisResult } from "@/types/analysis";

/**
 * Request handling shared by POST /api/analyze (JSON) and
 * POST /api/analyze/stream (SSE), so both enforce the same rate limit,
 * validation, persistence and error mapping.
 */

const bodySchema = z.object({ target: z.string().trim().min(1).max(2048) });

export const GENERIC_ANALYSIS_ERROR = "An unexpected error occurred while analyzing the target.";

export function jsonError(status: number, error: string, headers: Record<string, string> = {}): Response {
  return Response.json({ error }, { status, headers });
}

/**
 * Rate-limits, parses and validates an analyze request. Returns the trimmed
 * target and its cache key, or the error Response to send back.
 */
export async function readAnalyzeRequest(request: Request): Promise<{ target: string; cacheKey: string } | { response: Response }> {
  const rate = await rateLimiter.check(getClientIp(request.headers));
  if (!rate.allowed) {
    return {
      response: jsonError(429, "Rate limit exceeded. Please wait before analyzing another target.", {
        "Retry-After": Math.ceil(rate.retryAfterMs / 1000).toString(),
      }),
    };
  }

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return { response: jsonError(400, "Request body must be valid JSON.") };
  }

  const parsed = bodySchema.safeParse(body);
  if (!parsed.success) {
    return { response: jsonError(400, "A non-empty 'target' string is required.") };
  }
  return { target: parsed.data.target, cacheKey: parsed.data.target.toLowerCase() };
}

/** Persists a finished analysis; a storage failure is logged, never turned into a failed request. */
export async function persistAnalysis(result: AnalysisResult): Promise<void> {
  try {
    await saveAnalysis(result);
  } catch (err) {
    logger.error("store.persist_failed", { analysisId: result.id, ...errorFields(err) });
  }
}

/**
 * Maps a pipeline failure to what the client may see: validation and SSRF
 * rejections are the user's to fix and are shown as-is; anything else is
 * logged and replaced by a generic message so internals never leak.
 */
export function toClientError(err: unknown): { status: number; message: string } {
  if (err instanceof InvalidTargetError || err instanceof SsrfBlockedError) {
    return { status: 400, message: err.message };
  }
  logger.error("analysis.failed", errorFields(err));
  return { status: 500, message: GENERIC_ANALYSIS_ERROR };
}

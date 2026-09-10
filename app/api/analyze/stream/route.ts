import { NextRequest } from "next/server";
import { z } from "zod";
import { runAnalysis } from "@/services/orchestrator";
import { InvalidTargetError } from "@/lib/validation/target";
import { SsrfBlockedError } from "@/lib/security/ssrf";
import { saveAnalysis } from "@/lib/store";
import { getClientIp } from "@/lib/rateLimit";
import { rateLimiter, resultCache } from "@/lib/analyzeShared";
import type { PipelineStageResult } from "@/types/analysis";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
// Vercel-specific: raises the function timeout ceiling past the platform's
// default 10s (ignored as a no-op on non-Vercel Node hosts).
export const maxDuration = 60;

const bodySchema = z.object({ target: z.string().trim().min(1).max(2048) });

function sseEvent(event: Record<string, unknown>): Uint8Array {
  return new TextEncoder().encode(`data: ${JSON.stringify(event)}\n\n`);
}

/**
 * Server-Sent-Events variant of /api/analyze: streams each pipeline stage's
 * real completion as it happens, then the final normalized result. Used by
 * the analyze UI to render genuine backend progress instead of a fake timer.
 */
export async function POST(request: NextRequest) {
  const clientIp = getClientIp(request.headers);
  const rate = await rateLimiter.check(clientIp);
  if (!rate.allowed) {
    return new Response(JSON.stringify({ error: "Rate limit exceeded. Please wait before analyzing another target." }), {
      status: 429,
      headers: { "Retry-After": Math.ceil(rate.retryAfterMs / 1000).toString(), "Content-Type": "application/json" },
    });
  }

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return new Response(JSON.stringify({ error: "Request body must be valid JSON." }), {
      status: 400,
      headers: { "Content-Type": "application/json" },
    });
  }

  const parsed = bodySchema.safeParse(body);
  if (!parsed.success) {
    return new Response(JSON.stringify({ error: "A non-empty 'target' string is required." }), {
      status: 400,
      headers: { "Content-Type": "application/json" },
    });
  }

  const target = parsed.data.target;
  const cacheKey = target.toLowerCase();
  const cached = resultCache.get(cacheKey);

  const stream = new ReadableStream<Uint8Array>({
    async start(controller) {
      if (cached) {
        for (const stage of cached.pipeline) {
          controller.enqueue(sseEvent({ type: "stage", stage }));
        }
        controller.enqueue(sseEvent({ type: "result", data: cached }));
        controller.close();
        return;
      }

      try {
        const result = await runAnalysis(target, {
          onStage: (stage: PipelineStageResult) => controller.enqueue(sseEvent({ type: "stage", stage })),
        });
        resultCache.set(cacheKey, result);
        try {
          await saveAnalysis(result);
        } catch (err) {
          // The analysis itself succeeded — don't turn persistence failure
          // into an error event and discard a good result.
          console.error("Failed to persist analysis result:", err);
        }
        controller.enqueue(sseEvent({ type: "result", data: result }));
      } catch (err) {
        const message =
          err instanceof InvalidTargetError || err instanceof SsrfBlockedError
            ? err.message
            : "An unexpected error occurred while analyzing the target.";
        controller.enqueue(sseEvent({ type: "error", message }));
      } finally {
        controller.close();
      }
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream; charset=utf-8",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive",
    },
  });
}

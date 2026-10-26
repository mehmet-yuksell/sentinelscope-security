import { runAnalysis } from "@/services/orchestrator";
import { resultCache } from "@/lib/analyzeShared";
import { persistAnalysis, readAnalyzeRequest, toClientError } from "@/lib/analyzeRequest";
import type { PipelineStageResult } from "@/types/analysis";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
// Vercel-specific: raises the function timeout ceiling past the platform's
// default 10s (ignored as a no-op on non-Vercel Node hosts).
export const maxDuration = 60;

const encoder = new TextEncoder();

function sseEvent(event: Record<string, unknown>): Uint8Array {
  return encoder.encode(`data: ${JSON.stringify(event)}\n\n`);
}

/**
 * Server-Sent-Events variant of /api/analyze: streams each pipeline stage's
 * real completion as it happens, then the final normalized result. Used by
 * the analyze UI to render genuine backend progress instead of a fake timer.
 */
export async function POST(request: Request) {
  const parsed = await readAnalyzeRequest(request);
  if ("response" in parsed) return parsed.response;

  const { target, cacheKey } = parsed;
  const cached = resultCache.get(cacheKey);

  // Set once the client disconnects; later events are dropped instead of
  // throwing from enqueue() into the middle of the pipeline. The analysis
  // itself still finishes, so its result is cached and persisted.
  let clientGone = false;

  const stream = new ReadableStream<Uint8Array>({
    async start(controller) {
      const send = (event: Record<string, unknown>) => {
        if (clientGone) return;
        try {
          controller.enqueue(sseEvent(event));
        } catch {
          clientGone = true;
        }
      };
      const close = () => {
        if (clientGone) return;
        try {
          controller.close();
        } catch {
          clientGone = true;
        }
      };

      if (cached) {
        for (const stage of cached.pipeline) send({ type: "stage", stage });
        send({ type: "result", data: cached });
        close();
        return;
      }

      try {
        const result = await runAnalysis(target, {
          onStage: (stage: PipelineStageResult) => send({ type: "stage", stage }),
        });
        resultCache.set(cacheKey, result);
        await persistAnalysis(result);
        send({ type: "result", data: result });
      } catch (err) {
        send({ type: "error", message: toClientError(err).message });
      } finally {
        close();
      }
    },
    cancel() {
      clientGone = true;
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

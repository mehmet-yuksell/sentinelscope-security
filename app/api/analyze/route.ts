import { runAnalysis } from "@/services/orchestrator";
import { resultCache } from "@/lib/analyzeShared";
import { jsonError, persistAnalysis, readAnalyzeRequest, toClientError } from "@/lib/analyzeRequest";

// The pipeline opens raw TLS/DNS sockets, so it must run on the Node
// runtime rather than the Edge runtime.
export const runtime = "nodejs";
export const dynamic = "force-dynamic";
// Vercel-specific: the pipeline's sequential network stages can exceed the
// platform's default 10s function timeout; this raises the ceiling (ignored
// as a no-op on non-Vercel Node hosts).
export const maxDuration = 60;

export async function POST(request: Request) {
  const parsed = await readAnalyzeRequest(request);
  if ("response" in parsed) return parsed.response;

  const cached = resultCache.get(parsed.cacheKey);
  if (cached) {
    return Response.json(cached, { status: 200, headers: { "X-Cache": "HIT" } });
  }

  try {
    const result = await runAnalysis(parsed.target);
    resultCache.set(parsed.cacheKey, result);
    await persistAnalysis(result);
    return Response.json(result, { status: 200, headers: { "X-Cache": "MISS" } });
  } catch (err) {
    const { status, message } = toClientError(err);
    return jsonError(status, message);
  }
}

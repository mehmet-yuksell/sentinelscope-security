import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { runAnalysis } from "@/services/orchestrator";
import { InvalidTargetError } from "@/lib/validation/target";
import { SsrfBlockedError } from "@/lib/security/ssrf";
import { saveAnalysis } from "@/lib/store";
import { getClientIp } from "@/lib/rateLimit";
import { rateLimiter, resultCache } from "@/lib/analyzeShared";

// The pipeline opens raw TLS/DNS sockets, so it must run on the Node
// runtime rather than the Edge runtime.
export const runtime = "nodejs";
export const dynamic = "force-dynamic";
// Vercel-specific: the pipeline's sequential network stages can exceed the
// platform's default 10s function timeout; this raises the ceiling (ignored
// as a no-op on non-Vercel Node hosts).
export const maxDuration = 60;

const bodySchema = z.object({ target: z.string().trim().min(1).max(2048) });

export async function POST(request: NextRequest) {
  const clientIp = getClientIp(request.headers);
  const rate = await rateLimiter.check(clientIp);
  if (!rate.allowed) {
    return NextResponse.json(
      { error: "Rate limit exceeded. Please wait before analyzing another target." },
      { status: 429, headers: { "Retry-After": Math.ceil(rate.retryAfterMs / 1000).toString() } }
    );
  }

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: "Request body must be valid JSON." }, { status: 400 });
  }

  const parsed = bodySchema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json({ error: "A non-empty 'target' string is required." }, { status: 400 });
  }

  const cacheKey = parsed.data.target.toLowerCase();
  const cached = resultCache.get(cacheKey);
  if (cached) {
    return NextResponse.json(cached, { status: 200, headers: { "X-Cache": "HIT" } });
  }

  try {
    const result = await runAnalysis(parsed.data.target);
    resultCache.set(cacheKey, result);
    try {
      await saveAnalysis(result);
    } catch (err) {
      // The analysis itself succeeded — don't fail the request just because
      // persistence (e.g. a misconfigured or rate-limited store) did.
      console.error("Failed to persist analysis result:", err);
    }
    return NextResponse.json(result, { status: 200, headers: { "X-Cache": "MISS" } });
  } catch (err) {
    if (err instanceof InvalidTargetError || err instanceof SsrfBlockedError) {
      return NextResponse.json({ error: err.message }, { status: 400 });
    }
    console.error("Analysis pipeline failure:", err);
    return NextResponse.json({ error: "An unexpected error occurred while analyzing the target." }, { status: 500 });
  }
}

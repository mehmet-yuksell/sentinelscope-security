import { NextRequest } from "next/server";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { AnalysisResult } from "@/types/analysis";

const runAnalysisMock = vi.fn();
const saveAnalysisMock = vi.fn().mockResolvedValue(undefined);

vi.mock("@/services/orchestrator", () => ({
  runAnalysis: (...args: unknown[]) => runAnalysisMock(...args),
}));

vi.mock("@/lib/store", () => ({
  saveAnalysis: (...args: unknown[]) => saveAnalysisMock(...args),
}));

const { POST } = await import("@/app/api/analyze/route");

function makeFakeResult(target: string): AnalysisResult {
  return {
    id: `fake-${target}`,
    target,
    targetKind: "domain",
    hostname: target,
    timestamp: new Date().toISOString(),
    durationMs: 1,
    riskScore: 10,
    riskLevel: "very_low",
    risk: { score: 10, level: "very_low", factors: [], summary: "test" },
    dns: { status: "not_applicable" },
    tls: { status: "not_applicable" },
    http: { status: "not_applicable" },
    ip: { status: "not_applicable" },
    domain: { status: "not_applicable" },
    technologies: [],
    threatIntelligence: {
      virustotal: { status: "unavailable" },
      abuseipdb: { status: "unavailable" },
    },
    findings: [],
    pipeline: [],
  };
}

function postRequest(body: unknown, clientIp: string): NextRequest {
  return new NextRequest("http://localhost/api/analyze", {
    method: "POST",
    headers: { "Content-Type": "application/json", "x-forwarded-for": clientIp },
    body: typeof body === "string" ? body : JSON.stringify(body),
  });
}

describe("POST /api/analyze", () => {
  beforeEach(() => {
    runAnalysisMock.mockReset();
    saveAnalysisMock.mockClear();
  });

  it("rejects a request with invalid JSON", async () => {
    const res = await POST(postRequest("{not json", "1.1.1.10"));
    expect(res.status).toBe(400);
  });

  it("rejects a request missing the target field", async () => {
    const res = await POST(postRequest({}, "1.1.1.11"));
    expect(res.status).toBe(400);
  });

  it("rejects an empty target string", async () => {
    const res = await POST(postRequest({ target: "   " }, "1.1.1.12"));
    expect(res.status).toBe(400);
  });

  it("runs the pipeline and persists the result on success", async () => {
    const fakeResult = makeFakeResult("success-case.example");
    runAnalysisMock.mockResolvedValue(fakeResult);

    const res = await POST(postRequest({ target: "success-case.example" }, "1.1.1.13"));
    expect(res.status).toBe(200);
    expect(res.headers.get("X-Cache")).toBe("MISS");

    const body = await res.json();
    expect(body.id).toBe(fakeResult.id);
    expect(runAnalysisMock).toHaveBeenCalledWith("success-case.example");
    expect(saveAnalysisMock).toHaveBeenCalledWith(fakeResult);
  });

  it("serves a repeated identical target from cache without re-running the pipeline", async () => {
    const fakeResult = makeFakeResult("cache-case.example");
    runAnalysisMock.mockResolvedValue(fakeResult);

    const first = await POST(postRequest({ target: "cache-case.example" }, "1.1.1.14"));
    expect(first.headers.get("X-Cache")).toBe("MISS");

    const second = await POST(postRequest({ target: "cache-case.example" }, "1.1.1.14"));
    expect(second.headers.get("X-Cache")).toBe("HIT");

    expect(runAnalysisMock).toHaveBeenCalledTimes(1);
    expect(saveAnalysisMock).toHaveBeenCalledTimes(1);
  });

  it("translates an invalid-target error from the pipeline into a 400 response", async () => {
    const { InvalidTargetError } = await import("@/lib/validation/target");
    runAnalysisMock.mockRejectedValue(new InvalidTargetError("bad target"));

    const res = await POST(postRequest({ target: "whatever.example" }, "1.1.1.15"));
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error).toBe("bad target");
  });

  it("returns a 500 for an unexpected pipeline failure without leaking internals", async () => {
    runAnalysisMock.mockRejectedValue(new Error("boom: internal stack trace details"));

    const res = await POST(postRequest({ target: "explode.example" }, "1.1.1.16"));
    expect(res.status).toBe(500);
    const body = await res.json();
    expect(body.error).not.toMatch(/boom/);
  });

  it("enforces the per-IP rate limit", async () => {
    const fakeResult = makeFakeResult("rate-limit.example");
    runAnalysisMock.mockResolvedValue(fakeResult);
    const clientIp = "1.1.1.17";

    let lastStatus = 200;
    for (let i = 0; i < 15; i++) {
      // Vary the target so the cache doesn't short-circuit before the limiter is exercised.
      const res = await POST(postRequest({ target: `rate-limit-${i}.example` }, clientIp));
      lastStatus = res.status;
      if (lastStatus === 429) break;
    }

    expect(lastStatus).toBe(429);
  });

  it("returns the result even when persisting it fails", async () => {
    runAnalysisMock.mockResolvedValue(makeFakeResult("persist-fails.example"));
    saveAnalysisMock.mockRejectedValueOnce(new Error("redis down"));

    const res = await POST(postRequest({ target: "persist-fails.example" }, "1.1.1.18"));
    expect(res.status).toBe(200);
    expect((await res.json()).id).toBe("fake-persist-fails.example");
  });

  it("sends Retry-After with a 429", async () => {
    runAnalysisMock.mockImplementation(async (t: string) => makeFakeResult(t));
    let res: Response | undefined;
    for (let i = 0; i < 15; i++) {
      res = await POST(postRequest({ target: `retry-after-${i}.example` }, "1.1.1.19"));
      if (res.status === 429) break;
    }
    expect(res!.status).toBe(429);
    expect(Number(res!.headers.get("Retry-After"))).toBeGreaterThan(0);
  });
});

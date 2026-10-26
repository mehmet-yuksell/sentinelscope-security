import { beforeEach, describe, expect, it, vi } from "vitest";
import type { AnalysisResult, PipelineStageResult } from "@/types/analysis";

const runAnalysisMock = vi.fn();
const saveAnalysisMock = vi.fn();

vi.mock("@/services/orchestrator", () => ({
  runAnalysis: (...args: unknown[]) => runAnalysisMock(...args),
}));

vi.mock("@/lib/store", () => ({
  saveAnalysis: (...args: unknown[]) => saveAnalysisMock(...args),
}));

const { POST } = await import("@/app/api/analyze/stream/route");
const { InvalidTargetError } = await import("@/lib/validation/target");

const STAGES: PipelineStageResult[] = [
  { stage: "validation", status: "success", durationMs: 0 },
  { stage: "dns", status: "success", durationMs: 12 },
];

function fakeResult(target: string): AnalysisResult {
  return { id: `id-${target}`, target, pipeline: STAGES } as AnalysisResult;
}

/** Simulates the orchestrator: reports each stage, then resolves. */
function pipelineThatReportsStages(result: AnalysisResult) {
  return async (_target: string, options: { onStage?: (s: PipelineStageResult) => void }) => {
    for (const stage of STAGES) options.onStage?.(stage);
    return result;
  };
}

function post(body: unknown, clientIp: string): Request {
  return new Request("http://localhost/api/analyze/stream", {
    method: "POST",
    headers: { "Content-Type": "application/json", "x-forwarded-for": clientIp },
    body: typeof body === "string" ? body : JSON.stringify(body),
  });
}

async function readEvents(res: Response): Promise<Record<string, unknown>[]> {
  const text = await res.text();
  return text
    .split("\n\n")
    .filter((chunk) => chunk.startsWith("data: "))
    .map((chunk) => JSON.parse(chunk.slice(6)) as Record<string, unknown>);
}

describe("POST /api/analyze/stream", () => {
  beforeEach(() => {
    runAnalysisMock.mockReset();
    saveAnalysisMock.mockReset().mockResolvedValue(undefined);
  });

  it("streams each stage as it completes, then the result, and persists it", async () => {
    const result = fakeResult("stream.example");
    runAnalysisMock.mockImplementation(pipelineThatReportsStages(result));

    const res = await POST(post({ target: "  stream.example " }, "2.2.2.1"));
    expect(res.headers.get("Content-Type")).toMatch(/text\/event-stream/);

    const events = await readEvents(res);
    expect(events.map((e) => e.type)).toEqual(["stage", "stage", "result"]);
    expect((events[2]!.data as AnalysisResult).id).toBe(result.id);
    expect(runAnalysisMock).toHaveBeenCalledWith("stream.example", expect.any(Object));
    expect(saveAnalysisMock).toHaveBeenCalledWith(result);
  });

  it("replays a cached result's stages without re-running the pipeline", async () => {
    runAnalysisMock.mockImplementation(pipelineThatReportsStages(fakeResult("cached-stream.example")));
    await readEvents(await POST(post({ target: "cached-stream.example" }, "2.2.2.2")));

    const events = await readEvents(await POST(post({ target: "CACHED-stream.example" }, "2.2.2.2")));
    expect(events.map((e) => e.type)).toEqual(["stage", "stage", "result"]);
    expect(runAnalysisMock).toHaveBeenCalledTimes(1);
  });

  it("sends a validation error as an error event", async () => {
    runAnalysisMock.mockRejectedValue(new InvalidTargetError("Only ports 80 and 443 can be analyzed."));
    const events = await readEvents(await POST(post({ target: "https://x.example:22" }, "2.2.2.3")));
    expect(events).toEqual([{ type: "error", message: "Only ports 80 and 443 can be analyzed." }]);
  });

  it("hides internal error details behind a generic message", async () => {
    runAnalysisMock.mockRejectedValue(new Error("boom: secret internals"));
    const events = await readEvents(await POST(post({ target: "boom.example" }, "2.2.2.4")));
    expect(events).toHaveLength(1);
    expect(events[0]!.message).not.toMatch(/boom/);
  });

  it("still delivers the result when persisting it fails", async () => {
    runAnalysisMock.mockImplementation(pipelineThatReportsStages(fakeResult("persist-fails.example")));
    saveAnalysisMock.mockRejectedValue(new Error("redis down"));
    const events = await readEvents(await POST(post({ target: "persist-fails.example" }, "2.2.2.5")));
    expect(events.at(-1)!.type).toBe("result");
  });

  it("returns plain JSON errors before streaming starts", async () => {
    const badJson = await POST(post("{nope", "2.2.2.6"));
    expect(badJson.status).toBe(400);
    expect(await badJson.json()).toEqual({ error: "Request body must be valid JSON." });

    const missing = await POST(post({}, "2.2.2.6"));
    expect(missing.status).toBe(400);
  });

  it("enforces the shared rate limit", async () => {
    runAnalysisMock.mockImplementation(async (t: string) => fakeResult(t));
    let status = 200;
    for (let i = 0; i < 15 && status !== 429; i++) {
      const res = await POST(post({ target: `limit-${i}.example` }, "2.2.2.7"));
      status = res.status;
      await res.body?.cancel();
    }
    expect(status).toBe(429);
  });

  it("finishes the analysis without throwing when the client disconnects mid-stream", async () => {
    let releasePipeline!: () => void;
    const gate = new Promise<void>((resolve) => (releasePipeline = resolve));
    const result = fakeResult("disconnect.example");
    runAnalysisMock.mockImplementation(async (_t: string, options: { onStage?: (s: PipelineStageResult) => void }) => {
      await gate; // the client goes away while the pipeline is still running
      for (const stage of STAGES) options.onStage?.(stage);
      return result;
    });

    const res = await POST(post({ target: "disconnect.example" }, "2.2.2.8"));
    await res.body!.cancel();
    releasePipeline();

    await vi.waitFor(() => expect(saveAnalysisMock).toHaveBeenCalledWith(result));
  });
});

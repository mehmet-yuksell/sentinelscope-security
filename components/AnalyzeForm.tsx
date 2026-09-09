"use client";

import { useRouter } from "next/navigation";
import { useRef, useState } from "react";
import type { PipelineStage, PipelineStageResult } from "@/types/analysis";
import { PipelineProgress, STAGE_ORDER, type LiveStageStatus } from "@/components/PipelineProgress";

type Phase = "idle" | "running" | "error";

function emptyStatuses(): Record<PipelineStage, LiveStageStatus> {
  return Object.fromEntries(STAGE_ORDER.map((stage) => [stage, "pending"])) as Record<PipelineStage, LiveStageStatus>;
}

export function AnalyzeForm() {
  const router = useRouter();
  const [target, setTarget] = useState("");
  const [phase, setPhase] = useState<Phase>("idle");
  const [statuses, setStatuses] = useState<Record<PipelineStage, LiveStageStatus>>(emptyStatuses());
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const abortRef = useRef<AbortController | null>(null);

  async function handleSubmit(event: React.FormEvent) {
    event.preventDefault();
    const trimmed = target.trim();
    if (!trimmed || phase === "running") return;

    setPhase("running");
    setErrorMessage(null);
    const initial = emptyStatuses();
    initial.validation = "running";
    setStatuses(initial);

    const controller = new AbortController();
    abortRef.current = controller;

    try {
      const res = await fetch("/api/analyze/stream", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: trimmed }),
        signal: controller.signal,
      });

      if (!res.ok || !res.body) {
        const payload = await res.json().catch(() => ({ error: "The analysis request failed." }));
        throw new Error(payload.error ?? `Request failed with status ${res.status}.`);
      }

      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });

        const chunks = buffer.split("\n\n");
        buffer = chunks.pop() ?? "";

        for (const chunk of chunks) {
          const line = chunk.trim();
          if (!line.startsWith("data:")) continue;
          const payload = JSON.parse(line.slice(5).trim()) as
            | { type: "stage"; stage: PipelineStageResult }
            | { type: "result"; data: { id: string } }
            | { type: "error"; message: string };

          if (payload.type === "stage") {
            setStatuses((prev) => ({
              ...prev,
              [payload.stage.stage]: payload.stage.status === "success" ? "success" : payload.stage.status === "skipped" ? "skipped" : "failed",
            }));
          } else if (payload.type === "result") {
            router.push(`/analysis/${payload.data.id}`);
            return;
          } else if (payload.type === "error") {
            throw new Error(payload.message);
          }
        }
      }
    } catch (err) {
      if ((err as Error).name === "AbortError") return;
      setPhase("error");
      setErrorMessage((err as Error).message || "The analysis request failed.");
    }
  }

  return (
    <div className="flex w-full flex-col items-center gap-6">
      <form onSubmit={handleSubmit} className="flex w-full max-w-xl flex-col gap-3 sm:flex-row">
        <input
          type="text"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          placeholder="example.com, https://example.com, or 8.8.8.8"
          aria-label="Target domain, URL, or IP address"
          disabled={phase === "running"}
          className="card-elevated w-full flex-1 rounded-xl border border-base-600 bg-base-900 px-5 py-4 font-mono text-sm text-base-100 placeholder:text-base-500 transition focus:border-accent-500 focus:outline-none focus:ring-1 focus:ring-accent-500 disabled:opacity-60"
        />
        <button
          type="submit"
          disabled={phase === "running" || !target.trim()}
          className="glow-accent whitespace-nowrap rounded-xl bg-accent-500 px-7 py-4 text-sm font-bold text-base-950 transition hover:bg-accent-400 hover:shadow-accent-500/30 disabled:cursor-not-allowed disabled:opacity-50 disabled:shadow-none"
        >
          {phase === "running" ? "Analyzing…" : "Analyze Target"}
        </button>
      </form>
      <p className="text-xs font-medium uppercase tracking-[0.2em] text-base-500">
        Passive analysis · DNS · TLS · HTTP · Threat Intelligence
      </p>

      {phase === "running" && <PipelineProgress statuses={statuses} />}

      {phase === "error" && errorMessage && (
        <div className="w-full max-w-xl rounded-lg border border-risk-critical/40 bg-risk-critical/10 px-4 py-3 text-sm text-red-200">
          {errorMessage}
        </div>
      )}
    </div>
  );
}

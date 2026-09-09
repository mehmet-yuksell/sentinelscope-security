import type { PipelineStage } from "@/types/analysis";

export type LiveStageStatus = "pending" | "running" | "success" | "failed" | "skipped";

export const STAGE_ORDER: PipelineStage[] = [
  "validation",
  "dns",
  "ip",
  "tls",
  "http",
  "technology",
  "domain",
  "threat_intelligence",
  "risk_engine",
];

export const STAGE_LABEL: Record<PipelineStage, string> = {
  validation: "Target Validation",
  dns: "DNS Intelligence",
  ip: "IP Intelligence",
  tls: "TLS Analysis",
  http: "HTTP Analysis",
  technology: "Technology Detection",
  domain: "Domain Intelligence",
  threat_intelligence: "Threat Intelligence",
  risk_engine: "Risk Engine",
};

const STATUS_GLYPH: Record<LiveStageStatus, string> = {
  pending: "·",
  running: "◌",
  success: "✓",
  failed: "✕",
  skipped: "—",
};

const STATUS_CLASS: Record<LiveStageStatus, string> = {
  pending: "text-base-500",
  running: "text-accent-400 animate-pulse",
  success: "text-accent-500",
  failed: "text-risk-critical",
  skipped: "text-base-500",
};

interface PipelineProgressProps {
  statuses: Record<PipelineStage, LiveStageStatus>;
}

export function PipelineProgress({ statuses }: PipelineProgressProps) {
  return (
    <div className="card-elevated w-full max-w-md rounded-2xl border border-base-700 bg-base-900/70 p-6 font-mono text-sm backdrop-blur">
      <ul className="space-y-3">
        {STAGE_ORDER.map((stage) => {
          const status = statuses[stage] ?? "pending";
          return (
            <li key={stage} className="flex items-center justify-between gap-4">
              <span className={`font-medium tracking-wide ${status === "pending" ? "text-base-600" : "text-base-100"}`}>
                {STAGE_LABEL[stage].toUpperCase()}
              </span>
              <span
                className={`flex h-6 w-6 items-center justify-center rounded-full text-base ${STATUS_CLASS[status]}`}
                style={status === "success" ? { textShadow: "0 0 8px rgba(45, 212, 191, 0.7)" } : undefined}
              >
                {STATUS_GLYPH[status]}
              </span>
            </li>
          );
        })}
      </ul>
    </div>
  );
}

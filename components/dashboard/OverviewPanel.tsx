import type { AnalysisResult } from "@/types/analysis";
import { RiskScoreGauge } from "./RiskScoreGauge";
import { SecurityOverview } from "./SecurityOverview";
import { SecurityDna } from "./SecurityDna";
import { SEVERITY_COLOR, SEVERITY_LABEL } from "@/utils/riskDisplay";

export function OverviewPanel({ result }: { result: AnalysisResult }) {
  const topFindings = result.findings.slice(0, 4);

  return (
    <div className="space-y-6">
      <div className="grid gap-6 lg:grid-cols-[auto_1fr]">
        <div className="flex flex-col items-center justify-center rounded-xl border border-base-700 bg-base-900/50 p-6">
          <RiskScoreGauge score={result.riskScore} level={result.riskLevel} />
          <p className="mt-4 max-w-xs text-center text-xs text-base-500">{result.risk.summary}</p>
        </div>
        <SecurityOverview factors={result.risk.factors} />
      </div>

      <SecurityDna factors={result.risk.factors} />

      <div>
        <h3 className="mb-3 text-xs font-semibold uppercase tracking-widest text-base-500">Top Findings</h3>
        {topFindings.length === 0 ? (
          <p className="text-sm text-base-500">No findings were identified for this target.</p>
        ) : (
          <ul className="space-y-2">
            {topFindings.map((f) => (
              <li key={f.id} className="flex items-start gap-3 rounded-lg border border-base-800 bg-base-900/40 px-4 py-3">
                <span
                  className="mt-0.5 shrink-0 rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide"
                  style={{ color: SEVERITY_COLOR[f.severity], backgroundColor: `${SEVERITY_COLOR[f.severity]}1a` }}
                >
                  {SEVERITY_LABEL[f.severity]}
                </span>
                <span className="text-sm text-base-200">{f.title}</span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

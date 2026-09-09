import type { Finding } from "@/types/analysis";
import { SEVERITY_COLOR, SEVERITY_LABEL } from "@/utils/riskDisplay";

export function FindingsPanel({ findings }: { findings: Finding[] }) {
  if (findings.length === 0) {
    return (
      <div className="rounded-lg border border-dashed border-base-700 bg-base-900/40 px-4 py-8 text-center text-sm text-base-400">
        No findings were identified for this target.
      </div>
    );
  }

  return (
    <ul className="space-y-3">
      {findings.map((f) => (
        <li key={f.id} className="rounded-xl border border-base-700 bg-base-900/40 p-4">
          <div className="mb-2 flex flex-wrap items-center gap-2">
            <span
              className="rounded-full px-2.5 py-0.5 text-xs font-semibold uppercase tracking-wide"
              style={{ color: SEVERITY_COLOR[f.severity], backgroundColor: `${SEVERITY_COLOR[f.severity]}1a` }}
            >
              {SEVERITY_LABEL[f.severity]}
            </span>
            <h4 className="text-sm font-semibold text-base-100">{f.title}</h4>
          </div>
          <p className="text-sm text-base-300">{f.description}</p>
          {f.evidence && <p className="mt-2 break-all rounded bg-base-800/60 px-3 py-1.5 font-mono text-xs text-base-400">{f.evidence}</p>}
          <p className="mt-2 text-sm text-accent-400">
            Recommendation: <span className="text-base-300">{f.recommendation}</span>
          </p>
          <p className="mt-1 text-xs text-base-600">Source: {f.source}</p>
        </li>
      ))}
    </ul>
  );
}

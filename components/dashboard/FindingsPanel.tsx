import type { Finding } from "@/types/analysis";
import { SEVERITY_COLOR, SEVERITY_LABEL } from "@/utils/riskDisplay";

export function FindingsPanel({ findings }: { findings: Finding[] }) {
  if (findings.length === 0) {
    return (
      <div className="rounded-xl border border-dashed border-base-700 bg-base-900/40 px-4 py-10 text-center text-sm text-base-400">
        No findings were identified for this target.
      </div>
    );
  }

  return (
    <ul className="space-y-3.5">
      {findings.map((f) => (
        <li
          key={f.id}
          className="card-elevated rounded-2xl border border-base-700 border-l-[3px] bg-base-900/50 p-5 transition hover:border-base-600"
          style={{ borderLeftColor: SEVERITY_COLOR[f.severity] }}
        >
          <div className="mb-2.5 flex flex-wrap items-center gap-2.5">
            <span
              className="rounded-full px-2.5 py-1 text-[11px] font-bold uppercase tracking-wide"
              style={{ color: SEVERITY_COLOR[f.severity], backgroundColor: `${SEVERITY_COLOR[f.severity]}1a` }}
            >
              {SEVERITY_LABEL[f.severity]}
            </span>
            <h4 className="text-base font-bold text-base-50">{f.title}</h4>
          </div>
          <p className="text-sm leading-relaxed text-base-300">{f.description}</p>
          {f.evidence && (
            <p className="mt-2.5 break-all rounded-lg bg-base-950/60 px-3 py-2 font-mono text-xs text-base-400">{f.evidence}</p>
          )}
          <p className="mt-3 text-sm text-accent-400">
            <span className="font-semibold">Recommendation:</span> <span className="text-base-300">{f.recommendation}</span>
          </p>
          <p className="mt-1.5 text-xs font-medium text-base-600">Source: {f.source}</p>
        </li>
      ))}
    </ul>
  );
}

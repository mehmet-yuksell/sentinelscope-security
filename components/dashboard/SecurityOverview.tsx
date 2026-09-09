import type { RiskFactorScore } from "@/types/analysis";

interface SecurityOverviewProps {
  factors: RiskFactorScore[];
}

function healthColor(health: number): string {
  if (health >= 80) return "#2dd4bf";
  if (health >= 60) return "#60a5fa";
  if (health >= 40) return "#eab308";
  if (health >= 20) return "#f97316";
  return "#ef4444";
}

/** Inverts each risk factor's 0-100 risk score into a 0-100 "health" percentage — real data only, no fabricated bars. */
export function SecurityOverview({ factors }: SecurityOverviewProps) {
  return (
    <div className="rounded-xl border border-base-700 bg-base-900/50 p-5">
      <h3 className="mb-4 text-xs font-semibold uppercase tracking-widest text-base-500">Security Posture</h3>
      <ul className="space-y-3">
        {factors.map((factor) => {
          const health = factor.applicable ? 100 - factor.score : null;
          return (
            <li key={factor.key}>
              <div className="mb-1 flex items-center justify-between text-sm">
                <span className="text-base-200">{factor.label}</span>
                <span className="font-mono text-xs text-base-400">{health === null ? "N/A" : `${health}%`}</span>
              </div>
              <div className="h-1.5 w-full overflow-hidden rounded-full bg-base-800">
                {health !== null && (
                  <div
                    className="h-full rounded-full transition-all duration-700"
                    style={{ width: `${health}%`, backgroundColor: healthColor(health) }}
                  />
                )}
              </div>
            </li>
          );
        })}
      </ul>
    </div>
  );
}

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
    <div className="card-elevated rounded-2xl border border-base-700 bg-base-900/60 p-6">
      <h3 className="mb-5 text-xs font-bold uppercase tracking-widest text-base-500">Security Posture</h3>
      <ul className="space-y-4">
        {factors.map((factor) => {
          const health = factor.applicable ? 100 - factor.score : null;
          const color = health !== null ? healthColor(health) : "#3a4150";
          return (
            <li key={factor.key}>
              <div className="mb-1.5 flex items-center justify-between text-sm">
                <span className="font-medium text-base-200">{factor.label}</span>
                <span className="font-mono text-xs font-semibold" style={{ color: health === null ? "#5c6472" : color }}>
                  {health === null ? "N/A" : `${health}%`}
                </span>
              </div>
              <div className="h-2 w-full overflow-hidden rounded-full bg-base-800">
                {health !== null && (
                  <div
                    className="h-full rounded-full transition-all duration-700"
                    style={{ width: `${health}%`, backgroundColor: color, boxShadow: `0 0 8px ${color}66` }}
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

"use client";

import { PolarAngleAxis, PolarGrid, Radar, RadarChart, ResponsiveContainer } from "recharts";
import type { RiskFactorScore } from "@/types/analysis";

interface SecurityDnaProps {
  factors: RiskFactorScore[];
}

/** Visual signature of a target's security posture across every scored dimension. */
export function SecurityDna({ factors }: SecurityDnaProps) {
  const data = factors.map((factor) => ({
    label: factor.label,
    health: factor.applicable ? 100 - factor.score : 0,
  }));

  return (
    <div className="card-elevated rounded-2xl border border-base-700 bg-base-900/60 p-6">
      <h3 className="mb-2 text-xs font-bold uppercase tracking-widest text-base-500">Security DNA</h3>
      <div className="h-72 w-full sm:h-80">
        <ResponsiveContainer width="100%" height="100%">
          <RadarChart data={data} outerRadius="55%" margin={{ top: 16, right: 40, bottom: 16, left: 40 }}>
            <defs>
              <radialGradient id="securityDnaFill" cx="50%" cy="50%" r="65%">
                <stop offset="0%" stopColor="#2dd4bf" stopOpacity={0.45} />
                <stop offset="100%" stopColor="#2dd4bf" stopOpacity={0.08} />
              </radialGradient>
            </defs>
            <PolarGrid stroke="#2a303c" />
            <PolarAngleAxis dataKey="label" tick={{ fill: "#9ba3b3", fontSize: 10, fontWeight: 600 }} />
            <Radar
              dataKey="health"
              stroke="#2dd4bf"
              fill="url(#securityDnaFill)"
              strokeWidth={2.5}
              style={{ filter: "drop-shadow(0 0 6px rgba(45, 212, 191, 0.5))" }}
            />
          </RadarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

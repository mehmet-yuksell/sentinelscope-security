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
    <div className="rounded-xl border border-base-700 bg-base-900/50 p-5">
      <h3 className="mb-2 text-xs font-semibold uppercase tracking-widest text-base-500">Security DNA</h3>
      <div className="h-72 w-full sm:h-80">
        <ResponsiveContainer width="100%" height="100%">
          <RadarChart data={data} outerRadius="55%" margin={{ top: 16, right: 40, bottom: 16, left: 40 }}>
            <PolarGrid stroke="#2a303c" />
            <PolarAngleAxis dataKey="label" tick={{ fill: "#8b93a3", fontSize: 10 }} />
            <Radar dataKey="health" stroke="#2dd4bf" fill="#2dd4bf" fillOpacity={0.25} strokeWidth={2} />
          </RadarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

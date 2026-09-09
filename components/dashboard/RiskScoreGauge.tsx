"use client";

import type { RiskLevel } from "@/types/analysis";
import { RISK_LEVEL_COLOR, RISK_LEVEL_LABEL } from "@/utils/riskDisplay";

interface RiskScoreGaugeProps {
  score: number;
  level: RiskLevel;
}

const RADIUS = 70;
const CIRCUMFERENCE = 2 * Math.PI * RADIUS;

export function RiskScoreGauge({ score, level }: RiskScoreGaugeProps) {
  const color = RISK_LEVEL_COLOR[level];
  const offset = CIRCUMFERENCE * (1 - score / 100);

  return (
    <div className="flex flex-col items-center gap-2">
      <div
        className="relative h-44 w-44"
        style={
          {
            "--dash-full": CIRCUMFERENCE,
            "--dash-value": offset,
          } as React.CSSProperties
        }
      >
        <svg viewBox="0 0 160 160" className="h-full w-full -rotate-90">
          <circle cx="80" cy="80" r={RADIUS} fill="none" stroke="#1f242e" strokeWidth="12" />
          <circle
            cx="80"
            cy="80"
            r={RADIUS}
            fill="none"
            stroke={color}
            strokeWidth="12"
            strokeLinecap="round"
            strokeDasharray={CIRCUMFERENCE}
            strokeDashoffset={CIRCUMFERENCE}
            className="animate-scoreIn"
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-4xl font-bold text-base-50">{score}</span>
          <span className="text-xs text-base-500">/ 100</span>
        </div>
      </div>
      <span className="rounded-full px-3 py-1 text-xs font-semibold uppercase tracking-wide" style={{ color, backgroundColor: `${color}1a` }}>
        {RISK_LEVEL_LABEL[level]}
      </span>
    </div>
  );
}

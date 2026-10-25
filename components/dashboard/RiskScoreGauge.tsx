"use client";

import type { RiskLevel } from "@/types/analysis";
import { RISK_LEVEL_COLOR, RISK_LEVEL_LABEL, displayGrade, displayScore, hasRiskScore } from "@/utils/riskDisplay";

interface RiskScoreGaugeProps {
  score: number;
  level: RiskLevel;
}

const RADIUS = 70;
const CIRCUMFERENCE = 2 * Math.PI * RADIUS;

export function RiskScoreGauge({ score, level }: RiskScoreGaugeProps) {
  const color = RISK_LEVEL_COLOR[level];
  // With no data there is no arc to draw, rather than an arc at 0.
  const offset = hasRiskScore(level) ? CIRCUMFERENCE * (1 - score / 100) : CIRCUMFERENCE;
  const grade = displayGrade(score, level);

  return (
    <div className="flex flex-col items-center gap-3">
      <div
        className="relative h-48 w-48"
        style={
          {
            "--dash-full": CIRCUMFERENCE,
            "--dash-value": offset,
          } as React.CSSProperties
        }
      >
        <div className="absolute inset-6 rounded-full blur-2xl" style={{ backgroundColor: `${color}33` }} />
        <svg viewBox="0 0 160 160" className="relative h-full w-full -rotate-90">
          <circle cx="80" cy="80" r={RADIUS} fill="none" stroke="#1a1f28" strokeWidth="13" />
          <circle
            cx="80"
            cy="80"
            r={RADIUS}
            fill="none"
            stroke={color}
            strokeWidth="13"
            strokeLinecap="round"
            strokeDasharray={CIRCUMFERENCE}
            strokeDashoffset={CIRCUMFERENCE}
            className="animate-scoreIn"
            style={{ filter: `drop-shadow(0 0 10px ${color}99)` }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-6xl font-black tracking-tight" style={{ color }}>
            {grade}
          </span>
          <span className="mt-1 font-mono text-xs font-semibold text-base-400">{displayScore(score, level)} / 100</span>
        </div>
      </div>
      <span
        className="rounded-full px-4 py-1.5 text-xs font-bold uppercase tracking-wider"
        style={{ color, backgroundColor: `${color}1f`, boxShadow: `0 0 0 1px ${color}33` }}
      >
        {RISK_LEVEL_LABEL[level]}
      </span>
    </div>
  );
}

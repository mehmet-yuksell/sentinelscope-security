"use client";

import { PolarAngleAxis, PolarGrid, Radar, RadarChart, ResponsiveContainer } from "recharts";
import type { RiskFactorScore } from "@/types/analysis";
import { hostnameToHue } from "@/utils/riskDisplay";

interface SecurityDnaProps {
  factors: RiskFactorScore[];
  hostname: string;
}

// Short axis labels so they stay clear of the chart edge on narrow screens —
// full names are already shown in the Security Posture list above this.
const SHORT_LABEL: Record<string, string> = {
  tls: "TLS",
  http_headers: "HTTP Headers",
  dns_config: "DNS",
  domain_reputation: "Domain Rep.",
  ip_reputation: "IP Rep.",
  threat_intelligence: "Threat Intel",
  configuration: "Config",
};

/**
 * A per-target visual signature across every scored dimension — the hue is
 * deterministically derived from the hostname (not random per render), so
 * the same target always renders the same fingerprint while different
 * targets are visibly distinct from one another.
 */
export function SecurityDna({ factors, hostname }: SecurityDnaProps) {
  const hue = hostnameToHue(hostname);
  const stroke = `hsl(${hue}, 85%, 60%)`;
  const gradientId = `securityDnaFill-${hue}`;

  const data = factors.map((factor) => ({
    label: SHORT_LABEL[factor.key] ?? factor.label,
    health: factor.applicable ? 100 - factor.score : 0,
  }));

  return (
    <div className="card-elevated relative overflow-hidden rounded-2xl border border-base-700 bg-base-900/60 p-6">
      <div className="pointer-events-none absolute -left-16 -top-16 h-56 w-56 rounded-full blur-3xl" style={{ backgroundColor: `hsla(${hue}, 85%, 55%, 0.12)` }} />
      <div className="relative mb-1 flex items-baseline justify-between gap-2">
        <h3 className="text-xs font-bold uppercase tracking-widest text-base-500">Security DNA</h3>
        <span className="truncate font-mono text-[10px] text-base-600">fingerprint · {hostname}</span>
      </div>
      <div className="relative h-80 w-full sm:h-96">
        <ResponsiveContainer width="100%" height="100%">
          <RadarChart data={data} outerRadius="48%" margin={{ top: 16, right: 16, bottom: 16, left: 16 }}>
            <defs>
              <radialGradient id={gradientId} cx="50%" cy="50%" r="65%">
                <stop offset="0%" stopColor={stroke} stopOpacity={0.5} />
                <stop offset="100%" stopColor={stroke} stopOpacity={0.06} />
              </radialGradient>
            </defs>
            <PolarGrid stroke="#2a303c" />
            <PolarAngleAxis dataKey="label" tick={{ fill: "#9ba3b3", fontSize: 10, fontWeight: 600 }} />
            <Radar
              dataKey="health"
              stroke={stroke}
              fill={`url(#${gradientId})`}
              strokeWidth={3}
              style={{ filter: `drop-shadow(0 0 8px ${stroke})` }}
            />
          </RadarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

import type { FindingSeverity, HttpHeaderCheck, ProviderStatus, RiskLevel } from "@/types/analysis";

export const RISK_LEVEL_LABEL: Record<RiskLevel, string> = {
  very_low: "Very Low Risk",
  low: "Low Risk",
  moderate: "Moderate Risk",
  high: "High Risk",
  critical: "Critical Risk",
  insufficient_data: "Insufficient Data",
};

export const RISK_LEVEL_COLOR: Record<RiskLevel, string> = {
  very_low: "#2dd4bf",
  low: "#60a5fa",
  moderate: "#eab308",
  high: "#f97316",
  critical: "#ef4444",
  insufficient_data: "#5c6472",
};

/** False when no factor had usable data — the UI must then show "N/A", never a score or grade. */
export function hasRiskScore(level: RiskLevel): boolean {
  return level !== "insufficient_data";
}

export const SEVERITY_COLOR: Record<FindingSeverity, string> = {
  info: "#60a5fa",
  low: "#5eead4",
  medium: "#eab308",
  high: "#f97316",
  critical: "#ef4444",
};

export const SEVERITY_LABEL: Record<FindingSeverity, string> = {
  info: "Info",
  low: "Low",
  medium: "Medium",
  high: "High",
  critical: "Critical",
};

export const HEADER_STATUS_ICON: Record<HttpHeaderCheck["status"], string> = {
  pass: "✓",
  warning: "⚠",
  missing: "✕",
};

export const HEADER_STATUS_COLOR: Record<HttpHeaderCheck["status"], string> = {
  pass: "#2dd4bf",
  warning: "#eab308",
  missing: "#ef4444",
};

export const PROVIDER_STATUS_LABEL: Record<ProviderStatus, string> = {
  ok: "Available",
  unavailable: "Unavailable",
  error: "Error",
  not_applicable: "Not Applicable",
  demo: "Demo Data",
};

export type SecurityGrade = "A+" | "A" | "B" | "C" | "D" | "F";

/** A letter-grade complement to the numeric score — the pattern SSL Labs and
 * SecurityHeaders.com use, and a more immediately legible signal than a bare
 * percentage for "how good is this, at a glance". */
export function scoreToGrade(score: number): SecurityGrade {
  if (score < 5) return "A+";
  if (score < 20) return "A";
  if (score < 35) return "B";
  if (score < 50) return "C";
  if (score < 70) return "D";
  return "F";
}

/** Grade for display: "N/A" when there was no data to grade. */
export function displayGrade(score: number, level: RiskLevel): SecurityGrade | "N/A" {
  return hasRiskScore(level) ? scoreToGrade(score) : "N/A";
}

/** Score for display: "—" when there was no data to score. */
export function displayScore(score: number, level: RiskLevel): string {
  return hasRiskScore(level) ? String(score) : "—";
}

export const GRADE_COLOR: Record<SecurityGrade, string> = {
  "A+": "#2dd4bf",
  A: "#5eead4",
  B: "#60a5fa",
  C: "#eab308",
  D: "#f97316",
  F: "#ef4444",
};

/**
 * Deterministically maps a hostname to a hue within the brand's teal→blue→
 * violet range, so each target's "Security DNA" visual carries a subtle,
 * unique tint — a fingerprint, not a random color per render.
 */
export function hostnameToHue(hostname: string): number {
  let hash = 0;
  for (let i = 0; i < hostname.length; i++) {
    hash = (hash * 31 + hostname.charCodeAt(i)) >>> 0;
  }
  return 165 + (hash % 105); // 165 (teal) .. 270 (violet)
}

export function formatRelativeTime(isoTimestamp: string): string {
  const date = new Date(isoTimestamp);
  const diffMs = Date.now() - date.getTime();
  const diffSec = Math.floor(diffMs / 1000);
  if (diffSec < 60) return "just now";
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return `${diffMin} minute${diffMin === 1 ? "" : "s"} ago`;
  const diffHour = Math.floor(diffMin / 60);
  if (diffHour < 24) return `${diffHour} hour${diffHour === 1 ? "" : "s"} ago`;
  const diffDay = Math.floor(diffHour / 24);
  if (diffDay < 30) return `${diffDay} day${diffDay === 1 ? "" : "s"} ago`;
  return date.toLocaleDateString();
}

export function formatDate(isoTimestamp: string | null): string {
  if (!isoTimestamp) return "Unknown";
  return new Date(isoTimestamp).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}

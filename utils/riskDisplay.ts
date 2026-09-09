import type { FindingSeverity, HttpHeaderCheck, ProviderStatus, RiskLevel } from "@/types/analysis";

export const RISK_LEVEL_LABEL: Record<RiskLevel, string> = {
  very_low: "Very Low Risk",
  low: "Low Risk",
  moderate: "Moderate Risk",
  high: "High Risk",
  critical: "Critical Risk",
};

export const RISK_LEVEL_COLOR: Record<RiskLevel, string> = {
  very_low: "#2dd4bf",
  low: "#60a5fa",
  moderate: "#eab308",
  high: "#f97316",
  critical: "#ef4444",
};

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

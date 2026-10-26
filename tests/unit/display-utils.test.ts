import { describe, expect, it } from "vitest";
import { computeRisk } from "@/services/risk-engine";
import { displayGrade, displayScore, formatDate, formatRelativeTime, hasRiskScore, hostnameToHue, scoreToGrade } from "@/utils/riskDisplay";
import { summarizeDmarc, summarizeSpf } from "@/utils/emailDisplay";
import type { DmarcAnalysis, RiskLevel, SpfAnalysis } from "@/types/analysis";

describe("scoreToGrade", () => {
  it("uses the same bands as the risk levels and the Methodology page", () => {
    const cases: [number, string][] = [
      [0, "A+"], [4, "A+"], [5, "A"], [19, "A"], [20, "B"], [39, "B"],
      [40, "C"], [59, "C"], [60, "D"], [79, "D"], [80, "F"], [100, "F"],
    ];
    for (const [score, grade] of cases) expect(scoreToGrade(score), `score ${score}`).toBe(grade);
  });

  it("never disagrees with the risk level band for any score", () => {
    const gradeForLevel: Record<Exclude<RiskLevel, "insufficient_data">, string[]> = {
      very_low: ["A+", "A"], low: ["B"], moderate: ["C"], high: ["D"], critical: ["F"],
    };
    // Same bands as levelForScore() in services/risk-engine.
    for (let score = 0; score <= 100; score++) {
      const level = score < 20 ? "very_low" : score < 40 ? "low" : score < 60 ? "moderate" : score < 80 ? "high" : "critical";
      expect(gradeForLevel[level]).toContain(scoreToGrade(score));
    }
    // Spot-check against the engine itself.
    expect(computeRisk({
      dns: { status: "error" }, tls: { status: "not_applicable" }, http: { status: "error" }, domain: { status: "error" },
      threatIntelligence: { virustotal: { status: "unavailable" }, abuseipdb: { status: "unavailable" } },
    }).risk).toMatchObject({ score: 75, level: "high" });
    expect(scoreToGrade(75)).toBe("D");
  });
});

describe("display helpers for insufficient data", () => {
  it("shows N/A and a dash instead of a grade and score", () => {
    expect(hasRiskScore("insufficient_data")).toBe(false);
    expect(displayGrade(0, "insufficient_data")).toBe("N/A");
    expect(displayScore(0, "insufficient_data")).toBe("—");
    expect(displayGrade(3, "very_low")).toBe("A+");
    expect(displayScore(42, "moderate")).toBe("42");
  });
});

describe("formatting helpers", () => {
  it("derives a stable hue in the brand range from a hostname", () => {
    const hue = hostnameToHue("example.com");
    expect(hue).toBe(hostnameToHue("example.com"));
    expect(hue).toBeGreaterThanOrEqual(165);
    expect(hue).toBeLessThan(270);
  });

  it("formats relative times and handles missing dates", () => {
    const now = Date.now();
    expect(formatRelativeTime(new Date(now - 10_000).toISOString())).toBe("just now");
    expect(formatRelativeTime(new Date(now - 60_000).toISOString())).toBe("1 minute ago");
    expect(formatRelativeTime(new Date(now - 3 * 3_600_000).toISOString())).toBe("3 hours ago");
    expect(formatRelativeTime(new Date(now - 2 * 86_400_000).toISOString())).toBe("2 days ago");
    expect(formatDate(null)).toBe("Unknown");
    expect(formatDate("2026-01-15T00:00:00Z")).toMatch(/2026/);
  });
});

describe("email summaries", () => {
  const spf: SpfAnalysis = {
    record: "v=spf1 -all", recordCount: 1, allQualifier: "-", redirect: null, dnsLookups: 3,
    lookupLimitExceeded: false, includes: [], warnings: [], brokenReferences: [],
  };
  const dmarc: DmarcAnalysis = {
    record: "v=DMARC1; p=reject", foundAt: "_dmarc.example.com", inherited: false, recordCount: 1, valid: true,
    policy: "reject", subdomainPolicy: null, effectivePolicy: "reject", pct: 100, reportingUris: [],
  };

  it("summarizes SPF records", () => {
    expect(summarizeSpf(spf)).toBe("-all (fail: reject unlisted senders) · 3 of 10 DNS lookups");
    expect(summarizeSpf({ ...spf, recordCount: 0, record: null })).toBe("No SPF record");
    expect(summarizeSpf({ ...spf, recordCount: 2, record: null })).toMatch(/2 SPF records/);
    expect(summarizeSpf({ ...spf, allQualifier: null, lookupLimitExceeded: true })).toBe("no all mechanism (neutral) · over the 10-lookup limit");
  });

  it("summarizes DMARC records", () => {
    expect(summarizeDmarc(dmarc)).toBe("p=reject");
    expect(summarizeDmarc({ ...dmarc, inherited: true, effectivePolicy: "quarantine", pct: 25 })).toBe(
      "p=quarantine on 25% of mail (inherited from _dmarc.example.com)"
    );
    expect(summarizeDmarc({ ...dmarc, recordCount: 0 })).toBe("No DMARC record");
    expect(summarizeDmarc({ ...dmarc, recordCount: 2 })).toMatch(/Multiple/);
    expect(summarizeDmarc({ ...dmarc, valid: false, effectivePolicy: null })).toBe("Record has no valid policy");
  });
});

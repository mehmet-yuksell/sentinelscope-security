import { describe, expect, it } from "vitest";
import { computeRisk, type RiskEngineInput } from "@/services/risk-engine";
import type { DnsRecordSet, DomainIntelInfo, HttpInfo, ThreatIntelInfo, TlsInfo } from "@/types/analysis";

function baseInput(): RiskEngineInput {
  return {
    dns: { status: "error", message: "n/a" },
    tls: { status: "error", message: "n/a" },
    http: { status: "error", message: "n/a" },
    domain: { status: "error", message: "n/a" },
    threatIntelligence: {
      virustotal: { status: "unavailable" },
      abuseipdb: { status: "unavailable" },
    },
  };
}

const healthyTls: TlsInfo = {
  secure: true,
  tlsVersion: "TLSv1.3",
  issuer: "Let's Encrypt",
  subject: "example.com",
  validFrom: new Date(Date.now() - 30 * 86_400_000).toISOString(),
  validTo: new Date(Date.now() + 60 * 86_400_000).toISOString(),
  daysRemaining: 60,
  subjectAltNames: ["example.com"],
  selfSigned: false,
  authorized: true,
  authorizationError: null,
};

describe("computeRisk", () => {
  it("returns a score of 0 with an explanatory summary when no data is applicable", () => {
    const { risk, findings } = computeRisk(baseInput());
    expect(risk.score).toBe(0);
    expect(risk.factors.every((f) => !f.applicable)).toBe(true);
    expect(findings).toHaveLength(0);
    expect(risk.summary).toMatch(/insufficient data/i);
  });

  it("excludes unavailable factors from the weighted average instead of scoring them as safe or risky", () => {
    const input = baseInput();
    input.tls = { status: "ok", data: healthyTls };

    const { risk } = computeRisk(input);
    // Only the TLS factor is applicable; its near-zero risk score should dominate.
    const tlsFactor = risk.factors.find((f) => f.key === "tls")!;
    expect(tlsFactor.applicable).toBe(true);
    expect(risk.score).toBeLessThan(20);
  });

  it("scores an expired certificate as high risk and emits a critical finding", () => {
    const input = baseInput();
    input.tls = {
      status: "ok",
      data: { ...healthyTls, daysRemaining: -5, validTo: new Date(Date.now() - 5 * 86_400_000).toISOString() },
    };

    const { risk, findings } = computeRisk(input);
    expect(risk.score).toBeGreaterThan(30);
    expect(findings.some((f) => f.severity === "critical" && /expired/i.test(f.title))).toBe(true);
  });

  it("flags a target with no HTTPS support as a high-severity finding", () => {
    const input = baseInput();
    input.tls = { status: "not_applicable" };

    const { findings } = computeRisk(input);
    expect(findings.some((f) => f.severity === "high" && /https is not available/i.test(f.title))).toBe(true);
  });

  it("penalizes missing HTTP security headers proportionally to how many are missing", () => {
    const allMissing: HttpInfo = {
      finalUrl: "https://example.com/",
      statusCode: 200,
      redirected: false,
      redirectChain: [],
      headers: {},
      securityHeaders: [
        { header: "strict-transport-security", status: "missing", value: null, description: "" },
        { header: "content-security-policy", status: "missing", value: null, description: "" },
        { header: "x-content-type-options", status: "missing", value: null, description: "" },
        { header: "x-frame-options", status: "missing", value: null, description: "" },
        { header: "referrer-policy", status: "missing", value: null, description: "" },
        { header: "permissions-policy", status: "missing", value: null, description: "" },
      ],
      server: null,
      poweredBy: null,
    };

    const input = baseInput();
    input.http = { status: "ok", data: allMissing };

    const { risk, findings } = computeRisk(input);
    const headerFactor = risk.factors.find((f) => f.key === "http_headers")!;
    expect(headerFactor.score).toBeGreaterThanOrEqual(90);
    expect(findings.filter((f) => f.source === "HTTP Security Headers")).toHaveLength(6);
  });

  it("flags a newly registered domain as a high-risk finding", () => {
    const newDomain: DomainIntelInfo = {
      domain: "example.com",
      registrar: "Example Registrar",
      createdDate: new Date(Date.now() - 5 * 86_400_000).toISOString(),
      expiresDate: null,
      updatedDate: null,
      nameservers: [],
      domainAgeDays: 5,
      status: [],
    };

    const input = baseInput();
    input.domain = { status: "ok", data: newDomain };

    const { findings } = computeRisk(input);
    expect(findings.some((f) => /recently registered/i.test(f.title))).toBe(true);
  });

  it("uses AbuseIPDB confidence directly as the IP reputation score", () => {
    const threatIntelligence: ThreatIntelInfo = {
      virustotal: { status: "unavailable" },
      abuseipdb: {
        status: "ok",
        data: { provider: "AbuseIPDB", malicious: null, suspicious: null, harmless: null, totalEngines: null, abuseConfidenceScore: 87, totalReports: 42 },
      },
    };

    const input = baseInput();
    input.threatIntelligence = threatIntelligence;

    const { risk, findings } = computeRisk(input);
    const ipFactor = risk.factors.find((f) => f.key === "ip_reputation")!;
    expect(ipFactor.applicable).toBe(true);
    expect(ipFactor.score).toBe(87);
    expect(findings.some((f) => f.severity === "critical" && /abuse reports/i.test(f.title))).toBe(true);
  });

  it("sorts findings from most to least severe", () => {
    const input = baseInput();
    input.tls = { status: "not_applicable" }; // high severity finding
    const newDomain: DomainIntelInfo = {
      domain: "example.com",
      registrar: null,
      createdDate: new Date(Date.now() - 400 * 86_400_000).toISOString(),
      expiresDate: null,
      updatedDate: null,
      nameservers: [],
      domainAgeDays: 400,
      status: [],
    };
    input.dns = { status: "ok", data: { a: [], aaaa: [], mx: [], ns: ["ns1.example.com"], txt: [], cname: [], soa: null, caa: [], dmarcRecord: null } satisfies DnsRecordSet };
    input.domain = { status: "ok", data: newDomain };

    const { findings } = computeRisk(input);
    const severityRank: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
    for (let i = 1; i < findings.length; i++) {
      const previousRank = severityRank[findings[i - 1]!.severity] ?? 0;
      const currentRank = severityRank[findings[i]!.severity] ?? 0;
      expect(previousRank).toBeGreaterThanOrEqual(currentRank);
    }
  });
});

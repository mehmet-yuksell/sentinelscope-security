import { describe, expect, it } from "vitest";
import { computeRisk, type RiskEngineInput } from "@/services/risk-engine";
import type { DnsRecordSet, DomainIntelInfo, EmailSecurityInfo, HttpInfo, ThreatIntelInfo, TlsInfo } from "@/types/analysis";

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
  it("reports insufficient data — not a 'very low risk' verdict — when no factor is applicable", () => {
    const { risk, findings } = computeRisk(baseInput());
    expect(risk.level).toBe("insufficient_data");
    expect(risk.score).toBe(0);
    expect(risk.factors.every((f) => !f.applicable)).toBe(true);
    expect(findings).toHaveLength(0);
    expect(risk.summary).toMatch(/insufficient data/i);
  });

  it("assigns a real risk level as soon as one factor has usable data", () => {
    const input = baseInput();
    input.tls = { status: "ok", data: healthyTls };
    expect(computeRisk(input).risk.level).toBe("very_low");
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

/** A well-configured mail domain; tests override one aspect at a time. */
function goodEmail(overrides: Partial<EmailSecurityInfo> = {}): EmailSecurityInfo {
  return {
    domain: "example.com",
    organizationalDomain: "example.com",
    receivesMail: true,
    spf: {
      record: "v=spf1 include:_spf.example.net -all",
      recordCount: 1,
      allQualifier: "-",
      redirect: null,
      dnsLookups: 1,
      lookupLimitExceeded: false,
      includes: ["_spf.example.net"],
      warnings: [],
      brokenReferences: [],
    },
    dmarc: {
      record: "v=DMARC1; p=reject",
      foundAt: "_dmarc.example.com",
      inherited: false,
      recordCount: 1,
      valid: true,
      policy: "reject",
      subdomainPolicy: null,
      effectivePolicy: "reject",
      pct: 100,
      reportingUris: [],
    },
    mtaSts: { record: "v=STSv1; id=1", policyMode: "enforce", policyMaxAge: 86400, policyError: null },
    tlsRptRecord: null,
    ...overrides,
  };
}

function emailRisk(email: EmailSecurityInfo) {
  const input = baseInput();
  input.email = { status: "ok", data: email };
  const { risk, findings } = computeRisk(input);
  return { factor: risk.factors.find((f) => f.key === "email_security")!, findings };
}

describe("computeRisk — email security factor", () => {
  it("keeps the documented weights summing to 100%", () => {
    const { risk } = computeRisk(baseInput());
    expect(risk.factors.reduce((sum, f) => sum + f.weight, 0)).toBeCloseTo(1, 10);
  });

  it("scores a well-configured mail domain as low risk with no findings", () => {
    const { factor, findings } = emailRisk(goodEmail());
    expect(factor.applicable).toBe(true);
    expect(factor.score).toBe(5);
    expect(findings).toHaveLength(0);
  });

  it("is excluded — not scored as safe — when the domain neither receives mail nor publishes email policy", () => {
    const empty = goodEmail({ receivesMail: false });
    empty.spf = { ...empty.spf, record: null, recordCount: 0, allQualifier: null };
    empty.dmarc = { ...empty.dmarc, record: null, recordCount: 0, valid: false, policy: null, effectivePolicy: null };
    expect(emailRisk(empty).factor.applicable).toBe(false);
  });

  it("is excluded when the email stage failed or did not run", () => {
    const input = baseInput();
    input.email = { status: "error", message: "SERVFAIL" };
    expect(computeRisk(input).risk.factors.find((f) => f.key === "email_security")!.applicable).toBe(false);
  });

  it("flags missing SPF and DMARC on a domain that receives mail", () => {
    const email = goodEmail();
    email.spf = { ...email.spf, record: null, recordCount: 0, allQualifier: null };
    email.dmarc = { ...email.dmarc, record: null, recordCount: 0, valid: false, policy: null, effectivePolicy: null };
    const titles = emailRisk(email).findings.map((f) => f.title);
    expect(titles).toEqual(expect.arrayContaining(["No SPF record found", "No DMARC record found"]));
  });

  it("treats +all as high severity", () => {
    const email = goodEmail();
    email.spf = { ...email.spf, record: "v=spf1 +all", allQualifier: "+" };
    expect(emailRisk(email).findings).toContainEqual(expect.objectContaining({ severity: "high", title: "SPF record allows any sender (+all)" }));
  });

  it("flags the SPF lookup limit and broken include targets", () => {
    const email = goodEmail();
    email.spf = { ...email.spf, lookupLimitExceeded: true, dnsLookups: 11, brokenReferences: ["gone.example"] };
    const titles = emailRisk(email).findings.map((f) => f.title);
    expect(titles).toContain("SPF record exceeds the 10 DNS lookup limit");
    expect(titles).toContain("SPF record references a domain without a usable SPF record");
  });

  it("flags a monitoring-only DMARC policy, including one inherited from the organizational domain", () => {
    const email = goodEmail();
    email.dmarc = { ...email.dmarc, inherited: true, foundAt: "_dmarc.example.com", policy: "reject", subdomainPolicy: "none", effectivePolicy: "none" };
    const finding = emailRisk(email).findings.find((f) => f.title.startsWith("DMARC policy is monitoring-only"));
    expect(finding?.description).toMatch(/inherited from _dmarc\.example\.com/);
  });

  it("reports a missing MTA-STS policy as information only, without raising the score", () => {
    const { factor, findings } = emailRisk(goodEmail({ mtaSts: { record: null, policyMode: null, policyMaxAge: null, policyError: null } }));
    expect(findings).toEqual([expect.objectContaining({ severity: "info", title: "No MTA-STS policy" })]);
    expect(factor.score).toBe(5);
  });
});

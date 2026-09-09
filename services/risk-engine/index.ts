import type {
  DnsRecordSet,
  DomainIntelInfo,
  Finding,
  HttpInfo,
  ProviderResult,
  RiskAssessment,
  RiskFactorScore,
  RiskLevel,
  ThreatIntelInfo,
  TlsInfo,
} from "@/types/analysis";

let findingCounter = 0;
function nextFindingId(): string {
  findingCounter += 1;
  return `finding-${Date.now().toString(36)}-${findingCounter}`;
}

function finding(input: Omit<Finding, "id">): Finding {
  return { id: nextFindingId(), ...input };
}

interface FactorResult {
  key: string;
  label: string;
  weight: number;
  score: number | null; // null = not applicable, excluded from weighted average
  findings: Finding[];
}

const clamp = (value: number, min = 0, max = 100) => Math.min(max, Math.max(min, value));

// --- TLS Security -----------------------------------------------------

function scoreTls(tls: ProviderResult<TlsInfo>): FactorResult {
  const findings: Finding[] = [];
  const base: FactorResult = { key: "tls", label: "TLS Security", weight: 0.22, score: null, findings };

  if (tls.status === "not_applicable") {
    findings.push(
      finding({
        severity: "high",
        title: "HTTPS is not available",
        description: "The target did not accept a TLS connection on port 443. All traffic to this host is unencrypted.",
        recommendation: "Deploy a valid TLS certificate and serve the site exclusively over HTTPS.",
        source: "TLS Analysis",
      })
    );
    return { ...base, score: 75 };
  }
  if (tls.status !== "ok" || !tls.data) {
    return base; // handshake error / unknown — do not penalize on inconclusive data
  }

  const cert = tls.data;
  let score = 5;

  if (!cert.authorized) {
    score += 35;
    findings.push(
      finding({
        severity: "high",
        title: "TLS certificate is not trusted",
        description: `The presented certificate failed validation: ${cert.authorizationError ?? "unknown reason"}.`,
        evidence: cert.authorizationError ?? undefined,
        recommendation: "Install a certificate signed by a publicly trusted certificate authority.",
        source: "TLS Analysis",
      })
    );
  }
  if (cert.selfSigned) {
    score += 25;
    findings.push(
      finding({
        severity: "medium",
        title: "Self-signed certificate",
        description: "The certificate's issuer and subject are identical, indicating it was not issued by a trusted CA.",
        recommendation: "Replace the self-signed certificate with one from a trusted certificate authority.",
        source: "TLS Analysis",
      })
    );
  }
  if (cert.daysRemaining !== null) {
    if (cert.daysRemaining < 0) {
      score += 40;
      findings.push(
        finding({
          severity: "critical",
          title: "TLS certificate has expired",
          description: `The certificate expired ${Math.abs(cert.daysRemaining)} day(s) ago.`,
          evidence: cert.validTo ?? undefined,
          recommendation: "Renew the TLS certificate immediately.",
          source: "TLS Analysis",
        })
      );
    } else if (cert.daysRemaining < 14) {
      score += 20;
      findings.push(
        finding({
          severity: "medium",
          title: "TLS certificate expires soon",
          description: `The certificate expires in ${cert.daysRemaining} day(s).`,
          evidence: cert.validTo ?? undefined,
          recommendation: "Renew the TLS certificate before it expires to avoid a service disruption.",
          source: "TLS Analysis",
        })
      );
    } else if (cert.daysRemaining < 30) {
      score += 8;
    }
  }
  if (cert.tlsVersion && /TLSv1(\.0)?$|TLSv1\.1/i.test(cert.tlsVersion)) {
    score += 25;
    findings.push(
      finding({
        severity: "high",
        title: "Outdated TLS protocol version",
        description: `The server negotiated ${cert.tlsVersion}, which is deprecated and considered insecure.`,
        evidence: cert.tlsVersion,
        recommendation: "Disable TLS 1.0/1.1 and require TLS 1.2 or newer.",
        source: "TLS Analysis",
      })
    );
  }

  return { ...base, score: clamp(score) };
}

// --- HTTP Security Headers ---------------------------------------------

function scoreHttpHeaders(http: ProviderResult<HttpInfo>): FactorResult {
  const findings: Finding[] = [];
  const base: FactorResult = { key: "http_headers", label: "HTTP Security Headers", weight: 0.2, score: null, findings };

  if (http.status !== "ok" || !http.data) return base;

  let score = 0;
  for (const check of http.data.securityHeaders) {
    if (check.status === "missing") {
      score += 15;
      findings.push(
        finding({
          severity: "medium",
          title: `Missing ${check.header}`,
          description: `${check.description} This header was not present in the response.`,
          recommendation: `Add the ${check.header} header with an appropriate policy for this application.`,
          source: "HTTP Security Headers",
        })
      );
    } else if (check.status === "warning") {
      score += 7;
      findings.push(
        finding({
          severity: "low",
          title: `Weak ${check.header} configuration`,
          description: `${check.description} The current value may not provide the intended protection.`,
          evidence: check.value ?? undefined,
          recommendation: `Review and tighten the ${check.header} policy.`,
          source: "HTTP Security Headers",
        })
      );
    }
  }

  return { ...base, score: clamp(score) };
}

// --- DNS Configuration ---------------------------------------------------

function scoreDnsConfig(dns: ProviderResult<DnsRecordSet>): FactorResult {
  const findings: Finding[] = [];
  const base: FactorResult = { key: "dns_config", label: "DNS Configuration", weight: 0.12, score: null, findings };

  if (dns.status !== "ok" || !dns.data) return base;

  let score = 5;
  const data = dns.data;

  if (data.caa.length === 0) {
    score += 15;
    findings.push(
      finding({
        severity: "low",
        title: "No CAA record configured",
        description: "A Certificate Authority Authorization (CAA) record was not found, allowing any CA to issue certificates for this domain.",
        recommendation: "Publish a CAA record restricting certificate issuance to your chosen certificate authority.",
        source: "DNS Intelligence",
      })
    );
  }

  const hasSpf = data.txt.some((chunks) => chunks.join("").toLowerCase().startsWith("v=spf1"));
  if (data.mx.length > 0 && !hasSpf) {
    score += 20;
    findings.push(
      finding({
        severity: "medium",
        title: "No SPF record found",
        description: "The domain accepts mail (MX records present) but has no SPF record, making it easier to spoof sender addresses.",
        recommendation: "Publish an SPF TXT record authorizing legitimate mail servers.",
        source: "DNS Intelligence",
      })
    );
  }

  if (data.mx.length > 0 && !data.dmarcRecord) {
    score += 20;
    findings.push(
      finding({
        severity: "medium",
        title: "No DMARC record found",
        description: "No DMARC policy was found at _dmarc, reducing protection against email spoofing and phishing using this domain.",
        recommendation: "Publish a DMARC TXT record (starting with v=DMARC1) with at least a monitoring policy.",
        source: "DNS Intelligence",
      })
    );
  }

  if (data.ns.length === 1) {
    score += 10;
    findings.push(
      finding({
        severity: "low",
        title: "Single authoritative name server",
        description: "Only one NS record was found, which is a single point of failure for DNS resolution.",
        recommendation: "Configure at least two geographically diverse authoritative name servers.",
        source: "DNS Intelligence",
      })
    );
  }

  return { ...base, score: clamp(score) };
}

// --- Domain Reputation ----------------------------------------------------

function scoreDomainReputation(domain: ProviderResult<DomainIntelInfo>): FactorResult {
  const findings: Finding[] = [];
  const base: FactorResult = { key: "domain_reputation", label: "Domain Reputation", weight: 0.12, score: null, findings };

  if (domain.status !== "ok" || !domain.data) return base;

  let score = 5;
  const data = domain.data;

  if (data.domainAgeDays !== null) {
    if (data.domainAgeDays < 30) {
      score += 55;
      findings.push(
        finding({
          severity: "high",
          title: "Recently registered domain",
          description: `This domain was registered ${data.domainAgeDays} day(s) ago. Newly registered domains are disproportionately used for phishing and short-lived malicious campaigns.`,
          evidence: data.createdDate ?? undefined,
          recommendation: "Treat newly registered domains with additional scrutiny before trusting them.",
          source: "Domain Intelligence",
        })
      );
    } else if (data.domainAgeDays < 180) {
      score += 25;
      findings.push(
        finding({
          severity: "low",
          title: "Relatively new domain",
          description: `This domain is approximately ${Math.round(data.domainAgeDays / 30)} month(s) old.`,
          recommendation: "No immediate action required; age alone is not conclusive.",
          source: "Domain Intelligence",
        })
      );
    }
  }

  const holdStatus = data.status.find((s) => /hold/i.test(s));
  if (holdStatus) {
    score += 40;
    findings.push(
      finding({
        severity: "high",
        title: "Domain status flag indicates a hold",
        description: `RDAP reports a domain status of "${holdStatus}", which often signals a dispute, suspension, or registrar-level restriction.`,
        evidence: holdStatus,
        recommendation: "Investigate the domain status with the registrar or registry before proceeding.",
        source: "Domain Intelligence",
      })
    );
  }

  return { ...base, score: clamp(score) };
}

// --- IP Reputation ----------------------------------------------------

function scoreIpReputation(threatIntel: ThreatIntelInfo): FactorResult {
  const findings: Finding[] = [];
  const base: FactorResult = { key: "ip_reputation", label: "IP Reputation", weight: 0.12, score: null, findings };

  const abuse = threatIntel.abuseipdb;
  if (abuse.status !== "ok" || !abuse.data) return base;

  const confidence = abuse.data.abuseConfidenceScore ?? 0;
  if (confidence > 0) {
    findings.push(
      finding({
        severity: confidence >= 75 ? "critical" : confidence >= 40 ? "high" : confidence >= 10 ? "medium" : "low",
        title: "IP address has abuse reports",
        description: `AbuseIPDB reports an abuse confidence score of ${confidence}% based on ${abuse.data.totalReports ?? 0} report(s) in the last 90 days.`,
        evidence: `Abuse confidence: ${confidence}%`,
        recommendation: "Review AbuseIPDB's report history before trusting traffic to or from this address.",
        source: "AbuseIPDB",
      })
    );
  }

  return { ...base, score: clamp(confidence) };
}

// --- Threat Intelligence (VirusTotal) ----------------------------------

function scoreThreatIntelligence(threatIntel: ThreatIntelInfo): FactorResult {
  const findings: Finding[] = [];
  const base: FactorResult = { key: "threat_intelligence", label: "Threat Intelligence", weight: 0.14, score: null, findings };

  const vt = threatIntel.virustotal;
  if (vt.status !== "ok" || !vt.data) return base;

  const { malicious = 0, suspicious = 0, totalEngines } = vt.data;
  if ((malicious ?? 0) > 0 || (suspicious ?? 0) > 0) {
    findings.push(
      finding({
        severity: (malicious ?? 0) >= 3 ? "critical" : (malicious ?? 0) > 0 ? "high" : "medium",
        title: "Flagged by threat intelligence engines",
        description: `VirusTotal reports ${malicious ?? 0} malicious and ${suspicious ?? 0} suspicious verdict(s) out of ${totalEngines ?? "an unknown number of"} scanning engines.`,
        evidence: vt.data.reportUrl,
        recommendation: "Review the full VirusTotal report before trusting this target.",
        source: "VirusTotal",
      })
    );
  }

  const score = clamp((malicious ?? 0) * 15 + (suspicious ?? 0) * 7);
  return { ...base, score };
}

// --- Configuration Findings (catch-all) ---------------------------------

function scoreConfiguration(http: ProviderResult<HttpInfo>): FactorResult {
  const findings: Finding[] = [];
  const base: FactorResult = { key: "configuration", label: "Configuration Findings", weight: 0.08, score: null, findings };

  if (http.status !== "ok" || !http.data) return base;

  let score = 5;
  const data = http.data;

  if (data.server && /[\d]/.test(data.server)) {
    score += 15;
    findings.push(
      finding({
        severity: "low",
        title: "Server header discloses version information",
        description: `The Server header ("${data.server}") reveals specific software version details useful for targeting known vulnerabilities.`,
        evidence: data.server,
        recommendation: "Configure the web server to omit or generalize the Server header.",
        source: "HTTP Analysis",
      })
    );
  }

  if (data.poweredBy) {
    score += 10;
    findings.push(
      finding({
        severity: "info",
        title: "X-Powered-By header discloses technology stack",
        description: `The X-Powered-By header ("${data.poweredBy}") reveals backend technology details.`,
        evidence: data.poweredBy,
        recommendation: "Disable the X-Powered-By header in the application or reverse proxy configuration.",
        source: "HTTP Analysis",
      })
    );
  }

  if (data.finalUrl.startsWith("http://") && !data.redirected) {
    score += 25;
    findings.push(
      finding({
        severity: "medium",
        title: "Site is reachable over plain HTTP without a redirect",
        description: "The target served content over HTTP without redirecting to HTTPS.",
        recommendation: "Configure an automatic redirect from HTTP to HTTPS for all requests.",
        source: "HTTP Analysis",
      })
    );
  }

  return { ...base, score: clamp(score) };
}

function levelForScore(score: number): RiskLevel {
  if (score < 20) return "very_low";
  if (score < 40) return "low";
  if (score < 60) return "moderate";
  if (score < 80) return "high";
  return "critical";
}

const LEVEL_LABEL: Record<RiskLevel, string> = {
  very_low: "Very Low Risk",
  low: "Low Risk",
  moderate: "Moderate Risk",
  high: "High Risk",
  critical: "Critical Risk",
};

export interface RiskEngineInput {
  dns: ProviderResult<DnsRecordSet>;
  tls: ProviderResult<TlsInfo>;
  http: ProviderResult<HttpInfo>;
  domain: ProviderResult<DomainIntelInfo>;
  threatIntelligence: ThreatIntelInfo;
}

export interface RiskEngineOutput {
  risk: RiskAssessment;
  findings: Finding[];
}

/**
 * Computes a 0-100 risk score as a weighted average of independently scored
 * factors. A factor whose underlying data is unavailable (no API key,
 * failed lookup, not applicable) is excluded entirely and the remaining
 * weights are renormalized — missing data never silently reads as "safe"
 * or "risky".
 */
export function computeRisk(input: RiskEngineInput): RiskEngineOutput {
  const factors: FactorResult[] = [
    scoreTls(input.tls),
    scoreHttpHeaders(input.http),
    scoreDnsConfig(input.dns),
    scoreDomainReputation(input.domain),
    scoreIpReputation(input.threatIntelligence),
    scoreThreatIntelligence(input.threatIntelligence),
    scoreConfiguration(input.http),
  ];

  const applicable = factors.filter((f): f is FactorResult & { score: number } => f.score !== null);
  const totalWeight = applicable.reduce((sum, f) => sum + f.weight, 0);

  const score =
    totalWeight > 0
      ? Math.round(applicable.reduce((sum, f) => sum + (f.score * f.weight) / totalWeight, 0))
      : 0;

  const level = levelForScore(score);
  const findings = factors.flatMap((f) => f.findings);

  const factorScores: RiskFactorScore[] = factors.map((f) => ({
    key: f.key,
    label: f.label,
    score: f.score ?? 0,
    weight: f.weight,
    maxScore: 100,
    applicable: f.score !== null,
  }));

  const applicableCount = applicable.length;
  const summary =
    applicableCount === 0
      ? "Insufficient data was available to compute a confident risk assessment."
      : `Risk score derived from ${applicableCount} of ${factors.length} scoring factors with usable data. ${findings.length} finding(s) identified.`;

  return {
    risk: { score, level, factors: factorScores, summary },
    findings: findings.sort((a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity]),
  };
}

const SEVERITY_ORDER: Record<Finding["severity"], number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

export { LEVEL_LABEL };

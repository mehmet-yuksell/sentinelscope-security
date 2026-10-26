export type TargetKind = "domain" | "url" | "ipv4" | "ipv6";

export interface ParsedTarget {
  raw: string;
  kind: TargetKind;
  hostname: string;
  protocol: "http" | "https";
  port: number;
  displayName: string;
}

export type FindingSeverity = "info" | "low" | "medium" | "high" | "critical";

export interface Finding {
  id: string;
  severity: FindingSeverity;
  title: string;
  description: string;
  evidence?: string;
  recommendation: string;
  source: string;
}

export type ProviderStatus = "ok" | "unavailable" | "error" | "not_applicable" | "demo";

export interface ProviderResult<T> {
  status: ProviderStatus;
  message?: string;
  data?: T;
}

export interface DnsRecordSet {
  a: string[];
  aaaa: string[];
  mx: { priority: number; exchange: string }[];
  ns: string[];
  txt: string[][];
  cname: string[];
  soa: {
    nsname: string;
    hostmaster: string;
    serial: number;
    refresh: number;
    retry: number;
    expire: number;
    minttl: number;
  } | null;
  caa: { critical: number; iodef?: string; issue?: string; issuewild?: string }[];
  /** Set when `caa` came from a parent domain (RFC 8659 tree climbing) rather than the hostname itself. */
  caaInheritedFrom?: string;
  dmarcRecord: string | null;
}

export type SpfQualifier = "+" | "-" | "~" | "?";

export interface SpfAnalysis {
  /** The domain's SPF record, or null if there is none or more than one. */
  record: string | null;
  /** Number of `v=spf1` TXT records found; more than one is a permanent error (RFC 7208 §4.5). */
  recordCount: number;
  /** Qualifier of the top-level `all` mechanism, or null if the record has none. */
  allQualifier: SpfQualifier | null;
  /** Target of a `redirect=` modifier, if present. */
  redirect: string | null;
  /** DNS-querying terms counted through include/redirect chains; evaluation stops once past the limit. */
  dnsLookups: number;
  /** RFC 7208 §4.6.4: more than 10 DNS-querying terms makes SPF evaluation fail. */
  lookupLimitExceeded: boolean;
  /** include: targets at the top level of the record. */
  includes: string[];
  /** Problems found while following the record, e.g. an include with no SPF record. */
  warnings: string[];
}

export type DmarcPolicy = "none" | "quarantine" | "reject";

export interface DmarcAnalysis {
  record: string | null;
  /** The `_dmarc.` name the record was found at. */
  foundAt: string | null;
  /** True when the record came from the organizational domain rather than the hostname (RFC 7489 §6.6.3). */
  inherited: boolean;
  recordCount: number;
  /** False when a record exists but has no valid `p=` tag. */
  valid: boolean;
  policy: DmarcPolicy | null;
  subdomainPolicy: DmarcPolicy | null;
  /** The policy that applies to the analyzed hostname: `sp=` when inherited and present, otherwise `p=`. */
  effectivePolicy: DmarcPolicy | null;
  /** Percentage of failing mail the policy applies to (default 100). */
  pct: number;
  /** Aggregate report destinations (`rua=`). */
  reportingUris: string[];
}

export interface MtaStsAnalysis {
  /** The `_mta-sts.` TXT record (`v=STSv1; id=...`), if published. */
  record: string | null;
  /** Mode from the policy file at https://mta-sts.<domain>/.well-known/mta-sts.txt. */
  policyMode: "enforce" | "testing" | "none" | null;
  policyMaxAge: number | null;
  /** Why the policy file could not be read, when a TXT record exists but the policy is unusable. */
  policyError: string | null;
}

export interface EmailSecurityInfo {
  domain: string;
  organizationalDomain: string;
  /** True when the domain publishes MX records. */
  receivesMail: boolean;
  spf: SpfAnalysis;
  dmarc: DmarcAnalysis;
  mtaSts: MtaStsAnalysis;
  /** The `_smtp._tls.` TLS-RPT record, if published. */
  tlsRptRecord: string | null;
}

export interface TlsInfo {
  secure: boolean;
  tlsVersion: string | null;
  issuer: string | null;
  subject: string | null;
  validFrom: string | null;
  validTo: string | null;
  daysRemaining: number | null;
  subjectAltNames: string[];
  selfSigned: boolean;
  authorized: boolean;
  authorizationError: string | null;
}

export interface HttpHeaderCheck {
  header: string;
  status: "pass" | "warning" | "missing";
  value: string | null;
  description: string;
}

export interface HttpInfo {
  finalUrl: string;
  statusCode: number;
  redirected: boolean;
  redirectChain: string[];
  headers: Record<string, string>;
  securityHeaders: HttpHeaderCheck[];
  server: string | null;
  poweredBy: string | null;
}

export interface IpIntelInfo {
  ip: string;
  asn: string | null;
  organization: string | null;
  isp: string | null;
  country: string | null;
  countryCode: string | null;
  city: string | null;
  reverseDns: string | null;
  isDatacenter: boolean | null;
}

export interface DomainIntelInfo {
  domain: string;
  registrar: string | null;
  createdDate: string | null;
  expiresDate: string | null;
  updatedDate: string | null;
  nameservers: string[];
  domainAgeDays: number | null;
  status: string[];
}

export interface TechnologyEntry {
  category: string;
  name: string;
  confidence: "high" | "medium" | "low";
  evidence: string;
}

export interface ThreatIntelProviderFinding {
  provider: string;
  malicious: number | null;
  suspicious: number | null;
  harmless: number | null;
  totalEngines: number | null;
  reportUrl?: string;
  abuseConfidenceScore?: number;
  totalReports?: number;
}

export interface ThreatIntelInfo {
  virustotal: ProviderResult<ThreatIntelProviderFinding>;
  abuseipdb: ProviderResult<ThreatIntelProviderFinding>;
}

/**
 * "insufficient_data" means no risk factor had usable data, so there is no
 * score to report. `score` is 0 in that case and must not be displayed as one.
 */
export type RiskLevel = "very_low" | "low" | "moderate" | "high" | "critical" | "insufficient_data";

export interface RiskFactorScore {
  key: string;
  label: string;
  score: number;
  weight: number;
  maxScore: number;
  applicable: boolean;
}

export interface RiskAssessment {
  score: number;
  level: RiskLevel;
  factors: RiskFactorScore[];
  summary: string;
}

export interface PipelineStageResult {
  stage: PipelineStage;
  status: "success" | "skipped" | "failed";
  durationMs: number;
  error?: string;
}

export type PipelineStage =
  | "validation"
  | "dns"
  | "email"
  | "ip"
  | "tls"
  | "http"
  | "technology"
  | "domain"
  | "threat_intelligence"
  | "risk_engine";

export interface AnalysisResult {
  id: string;
  target: string;
  targetKind: TargetKind;
  hostname: string;
  timestamp: string;
  durationMs: number;
  riskScore: number;
  riskLevel: RiskLevel;
  risk: RiskAssessment;
  dns: ProviderResult<DnsRecordSet>;
  /** Absent on results stored before email security analysis existed. */
  email?: ProviderResult<EmailSecurityInfo>;
  tls: ProviderResult<TlsInfo>;
  http: ProviderResult<HttpInfo>;
  ip: ProviderResult<IpIntelInfo>;
  domain: ProviderResult<DomainIntelInfo>;
  technologies: TechnologyEntry[];
  threatIntelligence: ThreatIntelInfo;
  findings: Finding[];
  pipeline: PipelineStageResult[];
}

export interface HistoryEntry {
  id: string;
  target: string;
  timestamp: string;
  riskScore: number;
  riskLevel: RiskLevel;
}

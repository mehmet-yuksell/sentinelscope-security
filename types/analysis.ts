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
  dmarcRecord: string | null;
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

export type RiskLevel = "very_low" | "low" | "moderate" | "high" | "critical";

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

import { randomUUID } from "node:crypto";
import { parseTarget } from "@/lib/validation/target";
import { getRegistrableDomain } from "@/lib/dns/registrableDomain";
import { resolveAndAssertPublic } from "@/lib/security/ssrf";
import { analyzeDns } from "@/services/dns";
import { analyzeIp } from "@/services/ip";
import { analyzeTls } from "@/services/tls";
import { fetchTargetPage, buildHttpInfo } from "@/services/http";
import { detectTechnologies } from "@/services/technology";
import { analyzeDomain } from "@/services/domain";
import { analyzeThreatIntelligence } from "@/services/threat-intelligence";
import { computeRisk } from "@/services/risk-engine";
import type {
  AnalysisResult,
  DnsRecordSet,
  DomainIntelInfo,
  HttpInfo,
  IpIntelInfo,
  PipelineStage,
  PipelineStageResult,
  ProviderResult,
  TechnologyEntry,
  ThreatIntelInfo,
  TlsInfo,
} from "@/types/analysis";

export interface RunAnalysisOptions {
  /** Invoked synchronously as each pipeline stage finishes, for streaming progress to a client. */
  onStage?: (result: PipelineStageResult) => void;
}

async function runStage<T>(
  stage: PipelineStage,
  pipeline: PipelineStageResult[],
  fn: () => Promise<T>,
  skip: false | string = false,
  onStage?: (result: PipelineStageResult) => void
): Promise<T | undefined> {
  const start = Date.now();
  const record = (result: PipelineStageResult) => {
    pipeline.push(result);
    onStage?.(result);
  };

  if (skip) {
    record({ stage, status: "skipped", durationMs: 0, error: skip });
    return undefined;
  }
  try {
    const result = await fn();
    record({ stage, status: "success", durationMs: Date.now() - start });
    return result;
  } catch (err) {
    record({ stage, status: "failed", durationMs: Date.now() - start, error: (err as Error).message });
    return undefined;
  }
}

/**
 * Runs the full passive analysis pipeline for a single target:
 * validation -> DNS -> IP -> TLS -> HTTP -> technology -> domain ->
 * threat intelligence -> risk engine, producing one normalized
 * AnalysisResult the frontend never has to special-case per provider.
 * When `onStage` is provided, each stage's real completion is reported as
 * it happens so the UI can reflect actual backend progress, not a mock timer.
 */
export async function runAnalysis(rawTarget: string, options: RunAnalysisOptions = {}): Promise<AnalysisResult> {
  const { onStage } = options;
  const startedAt = Date.now();
  const pipeline: PipelineStageResult[] = [];

  const target = parseTarget(rawTarget); // throws InvalidTargetError -> handled by caller
  const validationResult: PipelineStageResult = { stage: "validation", status: "success", durationMs: 0 };
  pipeline.push(validationResult);
  onStage?.(validationResult);

  const isIpTarget = target.kind === "ipv4" || target.kind === "ipv6";

  const dns: ProviderResult<DnsRecordSet> =
    (await runStage(
      "dns",
      pipeline,
      () => analyzeDns(target.hostname),
      isIpTarget && "DNS record lookup does not apply to a literal IP target.",
      onStage
    )) ?? { status: "not_applicable" };

  let primaryIp: string | null = null;
  if (isIpTarget) {
    primaryIp = target.hostname;
  } else if (dns.status === "ok" && dns.data && dns.data.a.length > 0) {
    primaryIp = dns.data.a[0]!;
  } else {
    try {
      const resolved = await resolveAndAssertPublic(target.hostname);
      primaryIp = resolved.addresses[0] ?? null;
    } catch {
      primaryIp = null;
    }
  }

  const ip: ProviderResult<IpIntelInfo> =
    (await runStage(
      "ip",
      pipeline,
      () => analyzeIp(primaryIp!),
      !primaryIp && "No IP address could be resolved for this target.",
      onStage
    )) ?? { status: "not_applicable" };

  const tls: ProviderResult<TlsInfo> =
    (await runStage(
      "tls",
      pipeline,
      () => analyzeTls(target.hostname, target.port === 80 ? 443 : target.port),
      false,
      onStage
    )) ?? { status: "error", message: "TLS analysis did not complete." };

  let httpPageResponse: Awaited<ReturnType<typeof fetchTargetPage>> | null = null;
  const http: ProviderResult<HttpInfo> =
    (await runStage(
      "http",
      pipeline,
      async (): Promise<ProviderResult<HttpInfo>> => {
        httpPageResponse = await fetchTargetPage(target.hostname, target.protocol === "https" || tls.status === "ok");
        return { status: "ok", data: buildHttpInfo(httpPageResponse) };
      },
      false,
      onStage
    )) ?? { status: "error", message: "HTTP analysis did not complete." };

  const technologies: TechnologyEntry[] =
    (await runStage(
      "technology",
      pipeline,
      async () => detectTechnologies(httpPageResponse!),
      !httpPageResponse && "Technology detection requires a successful HTTP response.",
      onStage
    )) ?? [];

  const domain: ProviderResult<DomainIntelInfo> =
    (await runStage(
      "domain",
      pipeline,
      // Registries only hold records for registered domains, not subdomains.
      () => analyzeDomain(getRegistrableDomain(target.hostname)),
      isIpTarget && "Domain registration data does not apply to a literal IP target.",
      onStage
    )) ?? { status: "not_applicable" };

  const threatIntelligence: ThreatIntelInfo =
    (await runStage(
      "threat_intelligence",
      pipeline,
      () => analyzeThreatIntelligence(target.hostname, target.kind, primaryIp),
      false,
      onStage
    )) ?? {
      virustotal: { status: "error", message: "Threat intelligence did not complete." },
      abuseipdb: { status: "error", message: "Threat intelligence did not complete." },
    };

  const { risk, findings } =
    (await runStage(
      "risk_engine",
      pipeline,
      async () => computeRisk({ dns, tls, http, domain, threatIntelligence }),
      false,
      onStage
    )) ?? {
      risk: { score: 0, level: "insufficient_data" as const, factors: [], summary: "Risk engine did not complete." },
      findings: [],
    };

  return {
    id: randomUUID(),
    target: target.raw,
    targetKind: target.kind,
    hostname: target.hostname,
    timestamp: new Date().toISOString(),
    durationMs: Date.now() - startedAt,
    riskScore: risk.score,
    riskLevel: risk.level,
    risk,
    dns,
    tls,
    http,
    ip,
    domain,
    technologies,
    threatIntelligence,
    findings,
    pipeline,
  };
}

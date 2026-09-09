import type { ProviderResult, TargetKind, ThreatIntelInfo, ThreatIntelProviderFinding } from "@/types/analysis";

const REQUEST_TIMEOUT_MS = 8000;

interface FetchJsonResult {
  ok: boolean;
  status: number;
  json?: Record<string, unknown>;
  error?: string;
}

async function fetchJson(url: string, headers: Record<string, string>): Promise<FetchJsonResult> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    const res = await fetch(url, { headers, signal: controller.signal });
    const json = (await res.json().catch(() => undefined)) as Record<string, unknown> | undefined;
    return { ok: res.ok, status: res.status, json };
  } catch (err) {
    return { ok: false, status: 0, error: (err as Error).message };
  } finally {
    clearTimeout(timer);
  }
}

function get<T>(obj: unknown, path: string[]): T | undefined {
  let current: unknown = obj;
  for (const key of path) {
    if (typeof current !== "object" || current === null) return undefined;
    current = (current as Record<string, unknown>)[key];
  }
  return current as T | undefined;
}

async function queryVirusTotal(
  hostname: string,
  kind: TargetKind
): Promise<ProviderResult<ThreatIntelProviderFinding>> {
  const apiKey = process.env.VIRUSTOTAL_API_KEY;
  if (!apiKey) {
    return { status: "unavailable", message: "Configure VIRUSTOTAL_API_KEY to enable domain and IP reputation analysis." };
  }

  const isIpTarget = kind === "ipv4" || kind === "ipv6";
  const path = isIpTarget ? `ip_addresses/${hostname}` : `domains/${hostname}`;

  const result = await fetchJson(`https://www.virustotal.com/api/v3/${path}`, { "x-apikey": apiKey });

  if (result.status === 401 || result.status === 403) {
    return { status: "error", message: "VirusTotal rejected the configured API key." };
  }
  if (result.status === 429) {
    return { status: "error", message: "VirusTotal rate limit exceeded — try again shortly." };
  }
  if (!result.ok) {
    return { status: "error", message: result.error ?? `VirusTotal returned HTTP ${result.status}.` };
  }

  const stats = get<Record<string, number>>(result.json, ["data", "attributes", "last_analysis_stats"]);
  if (!stats) {
    return { status: "error", message: "VirusTotal response did not include analysis statistics." };
  }

  const totalEngines = Object.values(stats).reduce((sum, value) => sum + (Number(value) || 0), 0);

  return {
    status: "ok",
    data: {
      provider: "VirusTotal",
      malicious: stats.malicious ?? 0,
      suspicious: stats.suspicious ?? 0,
      harmless: stats.harmless ?? 0,
      totalEngines,
      reportUrl: `https://www.virustotal.com/gui/${isIpTarget ? "ip-address" : "domain"}/${hostname}`,
    },
  };
}

async function queryAbuseIpDb(ip: string | null): Promise<ProviderResult<ThreatIntelProviderFinding>> {
  const apiKey = process.env.ABUSEIPDB_API_KEY;
  if (!apiKey) {
    return { status: "unavailable", message: "Configure ABUSEIPDB_API_KEY to enable IP abuse-reputation analysis." };
  }
  if (!ip) {
    return { status: "not_applicable", message: "No IP address was available for this target." };
  }

  const result = await fetchJson(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`, {
    Key: apiKey,
    Accept: "application/json",
  });

  if (result.status === 401 || result.status === 403) {
    return { status: "error", message: "AbuseIPDB rejected the configured API key." };
  }
  if (result.status === 429) {
    return { status: "error", message: "AbuseIPDB rate limit exceeded — try again shortly." };
  }
  if (!result.ok) {
    return { status: "error", message: result.error ?? `AbuseIPDB returned HTTP ${result.status}.` };
  }

  const data = get<Record<string, unknown>>(result.json, ["data"]);
  if (!data) {
    return { status: "error", message: "AbuseIPDB response was empty." };
  }

  return {
    status: "ok",
    data: {
      provider: "AbuseIPDB",
      malicious: null,
      suspicious: null,
      harmless: null,
      totalEngines: null,
      abuseConfidenceScore: Number(data.abuseConfidenceScore ?? 0),
      totalReports: Number(data.totalReports ?? 0),
      reportUrl: `https://www.abuseipdb.com/check/${ip}`,
    },
  };
}

/**
 * Queries reputation providers in parallel. Each provider degrades to
 * "unavailable" independently when its API key is not configured — never
 * substituted with fabricated scores.
 */
export async function analyzeThreatIntelligence(
  hostname: string,
  kind: TargetKind,
  ip: string | null
): Promise<ThreatIntelInfo> {
  const [virustotal, abuseipdb] = await Promise.all([queryVirusTotal(hostname, kind), queryAbuseIpDb(ip)]);
  return { virustotal, abuseipdb };
}

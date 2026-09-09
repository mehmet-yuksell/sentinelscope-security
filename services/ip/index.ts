import { promises as dnsPromises } from "node:dns";
import type { IpIntelInfo, ProviderResult } from "@/types/analysis";

const REQUEST_TIMEOUT_MS = 6000;

// Heuristic only: derived from the real organization string returned by the
// provider, not an authoritative "hosting vs residential" classification.
const DATACENTER_KEYWORDS = [
  "amazon", "aws", "google", "microsoft", "azure", "digitalocean", "ovh", "hetzner",
  "linode", "vultr", "cloudflare", "oracle cloud", "alibaba", "scaleway", "contabo", "hostinger",
];

interface IpApiCoResponse {
  ip?: string;
  asn?: string;
  org?: string;
  country_name?: string;
  country_code?: string;
  city?: string;
  error?: boolean;
  reason?: string;
}

async function reverseLookup(ip: string): Promise<string | null> {
  try {
    const names = await dnsPromises.reverse(ip);
    return names[0] ?? null;
  } catch {
    return null;
  }
}

/**
 * Looks up ASN/organization/geolocation for a resolved IP via ipapi.co's
 * free, keyless JSON endpoint, plus a real reverse-DNS lookup. Returns
 * "unavailable" (never fabricated data) if the provider errors or rate-limits.
 */
export async function analyzeIp(ip: string): Promise<ProviderResult<IpIntelInfo>> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  try {
    const res = await fetch(`https://ipapi.co/${encodeURIComponent(ip)}/json/`, {
      signal: controller.signal,
      headers: { "User-Agent": "SentinelScope/1.0 (+passive-security-scanner)" },
    });

    if (!res.ok) {
      return { status: "unavailable", message: `IP intelligence provider returned HTTP ${res.status}.` };
    }

    const json = (await res.json()) as IpApiCoResponse;
    if (json.error) {
      return { status: "unavailable", message: json.reason ?? "IP intelligence lookup failed." };
    }

    const reverseDns = await reverseLookup(ip);
    const org = json.org ?? null;
    const isDatacenter = org ? DATACENTER_KEYWORDS.some((kw) => org.toLowerCase().includes(kw)) : null;

    const data: IpIntelInfo = {
      ip: json.ip ?? ip,
      asn: json.asn ?? null,
      organization: org,
      isp: org,
      country: json.country_name ?? null,
      countryCode: json.country_code ?? null,
      city: json.city ?? null,
      reverseDns,
      isDatacenter,
    };

    return { status: "ok", data };
  } catch (err) {
    return { status: "unavailable", message: `IP intelligence provider unreachable: ${(err as Error).message}` };
  } finally {
    clearTimeout(timer);
  }
}

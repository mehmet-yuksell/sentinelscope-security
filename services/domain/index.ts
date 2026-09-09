import type { DomainIntelInfo, ProviderResult } from "@/types/analysis";

const REQUEST_TIMEOUT_MS = 7000;

interface RdapEvent {
  eventAction: string;
  eventDate: string;
}

interface RdapEntity {
  roles?: string[];
  handle?: string;
  vcardArray?: [string, unknown[]];
}

interface RdapNameserver {
  ldhName?: string;
}

interface RdapResponse {
  ldhName?: string;
  status?: string[];
  events?: RdapEvent[];
  nameservers?: RdapNameserver[];
  entities?: RdapEntity[];
}

function findEventDate(events: RdapEvent[] | undefined, action: string): string | null {
  return events?.find((event) => event.eventAction === action)?.eventDate ?? null;
}

function findRegistrarName(entities: RdapEntity[] | undefined): string | null {
  const registrar = entities?.find((entity) => entity.roles?.includes("registrar"));
  if (!registrar) return null;
  const vcardFields = registrar.vcardArray?.[1];
  if (Array.isArray(vcardFields)) {
    const fn = vcardFields.find((field): field is unknown[] => Array.isArray(field) && field[0] === "fn");
    if (fn && typeof fn[3] === "string") return fn[3];
  }
  return registrar.handle ?? null;
}

/**
 * Looks up registration data via the free, keyless RDAP protocol (the
 * IETF-standardized successor to WHOIS), routed through rdap.org's bootstrap
 * so the correct registry is queried regardless of TLD.
 */
export async function analyzeDomain(domain: string): Promise<ProviderResult<DomainIntelInfo>> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  try {
    const res = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
      signal: controller.signal,
      headers: { Accept: "application/rdap+json", "User-Agent": "SentinelScope/1.0 (+passive-security-scanner)" },
    });

    if (res.status === 404) {
      return { status: "unavailable", message: "No RDAP record found (domain may be unregistered or on an unsupported TLD)." };
    }
    if (!res.ok) {
      return { status: "unavailable", message: `RDAP lookup returned HTTP ${res.status}.` };
    }

    const json = (await res.json()) as RdapResponse;
    const createdDate = findEventDate(json.events, "registration");
    const domainAgeDays = createdDate
      ? Math.max(0, Math.floor((Date.now() - new Date(createdDate).getTime()) / (1000 * 60 * 60 * 24)))
      : null;

    const data: DomainIntelInfo = {
      domain,
      registrar: findRegistrarName(json.entities),
      createdDate,
      expiresDate: findEventDate(json.events, "expiration"),
      updatedDate: findEventDate(json.events, "last changed"),
      nameservers: (json.nameservers ?? []).map((ns) => ns.ldhName).filter((n): n is string => Boolean(n)),
      domainAgeDays,
      status: json.status ?? [],
    };

    return { status: "ok", data };
  } catch (err) {
    return { status: "unavailable", message: `RDAP lookup failed: ${(err as Error).message}` };
  } finally {
    clearTimeout(timer);
  }
}

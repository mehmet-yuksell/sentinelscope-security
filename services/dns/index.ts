import { promises as dnsPromises, type SoaRecord, type CaaRecord } from "node:dns";
import type { DnsRecordSet, ProviderResult } from "@/types/analysis";

async function safe<T>(fn: () => Promise<T>, fallback: T): Promise<T> {
  try {
    return await fn();
  } catch {
    return fallback;
  }
}

/**
 * CAA records apply to every name below the domain that publishes them
 * (RFC 8659 §3): a CA checks the hostname, then each parent in turn, and uses
 * the first non-empty set it finds. Looking only at the exact hostname would
 * report "no CAA" for e.g. api.github.com even though github.com restricts
 * issuance for it. Stops before the bare TLD.
 */
export async function resolveCaaWithInheritance(
  hostname: string,
  resolve: (name: string) => Promise<CaaRecord[]> = (name) => dnsPromises.resolveCaa(name)
): Promise<{ records: CaaRecord[]; foundAt: string | null }> {
  const labels = hostname.split(".");
  for (let i = 0; labels.length - i >= 2; i++) {
    const name = labels.slice(i).join(".");
    const records = await safe(() => resolve(name), [] as CaaRecord[]);
    if (records.length > 0) return { records, foundAt: name };
  }
  return { records: [], foundAt: null };
}

/**
 * Resolves the standard DNS record types for a hostname. Each record type is
 * queried independently and tolerantly — a missing record type (e.g. no MX)
 * is not an error, only an empty result for that type.
 */
export async function analyzeDns(hostname: string): Promise<ProviderResult<DnsRecordSet>> {
  try {
    const [a, aaaa, mx, ns, txt, cname, soa, caa, dmarcTxt] = await Promise.all([
      safe(() => dnsPromises.resolve4(hostname), [] as string[]),
      safe(() => dnsPromises.resolve6(hostname), [] as string[]),
      safe(() => dnsPromises.resolveMx(hostname), [] as { priority: number; exchange: string }[]),
      safe(() => dnsPromises.resolveNs(hostname), [] as string[]),
      safe(() => dnsPromises.resolveTxt(hostname), [] as string[][]),
      safe(() => dnsPromises.resolveCname(hostname), [] as string[]),
      safe(() => dnsPromises.resolveSoa(hostname), null as SoaRecord | null),
      resolveCaaWithInheritance(hostname),
      safe(() => dnsPromises.resolveTxt(`_dmarc.${hostname}`), [] as string[][]),
    ]);
    const dmarcRecord = dmarcTxt.map((chunks) => chunks.join("")).find((v) => v.startsWith("v=DMARC1")) ?? null;

    const hasAnyRecord =
      a.length > 0 ||
      aaaa.length > 0 ||
      mx.length > 0 ||
      ns.length > 0 ||
      txt.length > 0 ||
      cname.length > 0 ||
      soa !== null ||
      caa.foundAt === hostname; // CAA inherited from a parent says nothing about whether this name exists

    if (!hasAnyRecord) {
      return { status: "error", message: `No DNS records were found for ${hostname}.` };
    }

    const data: DnsRecordSet = {
      a,
      aaaa,
      mx: mx.sort((x, y) => x.priority - y.priority),
      ns,
      txt,
      cname,
      soa: soa
        ? {
            nsname: soa.nsname,
            hostmaster: soa.hostmaster,
            serial: soa.serial,
            refresh: soa.refresh,
            retry: soa.retry,
            expire: soa.expire,
            minttl: soa.minttl,
          }
        : null,
      caa: caa.records.map((record) => ({
        critical: record.critical,
        iodef: record.iodef,
        issue: record.issue,
        issuewild: record.issuewild,
      })),
      ...(caa.foundAt && caa.foundAt !== hostname ? { caaInheritedFrom: caa.foundAt } : {}),
      dmarcRecord,
    };

    return { status: "ok", data };
  } catch (err) {
    return { status: "error", message: `DNS resolution failed: ${(err as Error).message}` };
  }
}

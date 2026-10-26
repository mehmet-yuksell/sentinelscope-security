import type { DmarcAnalysis, SpfAnalysis, SpfQualifier } from "@/types/analysis";

export const SPF_ALL_LABEL: Record<SpfQualifier, string> = {
  "-": "-all (fail: reject unlisted senders)",
  "~": "~all (softfail: accept but mark unlisted senders)",
  "?": "?all (neutral: no instruction)",
  "+": "+all (pass: any server may send)",
};

/** One-line SPF verdict for the dashboard and the printable report. */
export function summarizeSpf(spf: SpfAnalysis): string {
  if (spf.recordCount === 0) return "No SPF record";
  if (spf.recordCount > 1) return `${spf.recordCount} SPF records (invalid — only one is allowed)`;
  const all = spf.allQualifier ? SPF_ALL_LABEL[spf.allQualifier] : "no all mechanism (neutral)";
  const lookups = spf.lookupLimitExceeded ? "over the 10-lookup limit" : `${spf.dnsLookups} of 10 DNS lookups`;
  return `${all} · ${lookups}`;
}

/** One-line DMARC verdict for the dashboard and the printable report. */
export function summarizeDmarc(dmarc: DmarcAnalysis): string {
  if (dmarc.recordCount === 0) return "No DMARC record";
  if (dmarc.recordCount > 1) return "Multiple DMARC records (no policy applies)";
  if (!dmarc.valid || !dmarc.effectivePolicy) return "Record has no valid policy";
  const inherited = dmarc.inherited ? ` (inherited from ${dmarc.foundAt})` : "";
  const pct = dmarc.pct < 100 ? ` on ${dmarc.pct}% of mail` : "";
  return `p=${dmarc.effectivePolicy}${pct}${inherited}`;
}

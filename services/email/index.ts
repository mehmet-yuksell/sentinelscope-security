import { promises as dnsPromises } from "node:dns";
import { safeRequest } from "@/lib/net/safeRequest";
import { getRegistrableDomain } from "@/lib/dns/registrableDomain";
import type {
  DmarcAnalysis,
  DmarcPolicy,
  EmailSecurityInfo,
  MtaStsAnalysis,
  ProviderResult,
  SpfAnalysis,
  SpfQualifier,
} from "@/types/analysis";

/** RFC 7208 §4.6.4: at most 10 DNS-querying terms per SPF evaluation. */
export const SPF_LOOKUP_LIMIT = 10;
const MAX_SPF_DEPTH = 10;
const MTA_STS_TIMEOUT_MS = 5000;

export interface EmailDeps {
  resolveTxt(name: string): Promise<string[][]>;
  resolveMx(name: string): Promise<{ priority: number; exchange: string }[]>;
  fetchText(url: string): Promise<{ statusCode: number; body: string }>;
}

const defaultDeps: EmailDeps = {
  resolveTxt: (name) => dnsPromises.resolveTxt(name),
  resolveMx: (name) => dnsPromises.resolveMx(name),
  // Goes through the SSRF guard like every other request to a
  // target-derived host. RFC 8461 §3.3: policy fetches must not follow redirects.
  fetchText: (url) => safeRequest(url, { timeoutMs: MTA_STS_TIMEOUT_MS, maxRedirects: 0, maxBodyBytes: 64 * 1024 }),
};

// --- DNS helpers ------------------------------------------------------------

function isNoRecordError(err: unknown): boolean {
  const code = (err as NodeJS.ErrnoException).code;
  return code === "ENODATA" || code === "ENOTFOUND";
}

/**
 * TXT records joined into strings. "No such record" is an empty list; any
 * other failure (SERVFAIL, timeout) throws, so an unreachable resolver is
 * never mistaken for a domain that publishes nothing.
 */
async function lookupTxt(deps: EmailDeps, name: string): Promise<string[]> {
  try {
    return (await deps.resolveTxt(name)).map((chunks) => chunks.join(""));
  } catch (err) {
    if (isNoRecordError(err)) return [];
    throw new Error(`TXT lookup for ${name} failed: ${(err as Error).message}`);
  }
}

async function lookupMx(deps: EmailDeps, name: string): Promise<{ priority: number; exchange: string }[]> {
  try {
    return await deps.resolveMx(name);
  } catch (err) {
    if (isNoRecordError(err)) return [];
    throw new Error(`MX lookup for ${name} failed: ${(err as Error).message}`);
  }
}

// --- SPF --------------------------------------------------------------------

export function findSpfRecords(txt: string[]): string[] {
  return txt.filter((record) => /^v=spf1(\s|$)/i.test(record.trim()));
}

export interface SpfTerm {
  kind: "mechanism" | "modifier";
  qualifier: SpfQualifier;
  name: string;
  /** Domain argument with any CIDR suffix removed, or null. */
  value: string | null;
}

export function parseSpfTerms(record: string): SpfTerm[] {
  return record
    .trim()
    .split(/\s+/)
    .slice(1) // drop "v=spf1"
    .map((token): SpfTerm => {
      const modifier = /^([a-z][a-z0-9_.-]*)=(.*)$/i.exec(token);
      if (modifier) {
        return { kind: "modifier", qualifier: "+", name: modifier[1]!.toLowerCase(), value: modifier[2] || null };
      }
      const qualifier = "+-~?".includes(token[0]!) ? (token[0] as SpfQualifier) : "+";
      const body = qualifier === token[0] ? token.slice(1) : token;
      const [name, arg] = body.split(/:(.*)/s);
      const value = arg ? arg.split("/")[0]! : null;
      return { kind: "mechanism", qualifier, name: name!.toLowerCase().split("/")[0]!, value };
    });
}

const LOOKUP_MECHANISMS = new Set(["include", "a", "mx", "ptr", "exists"]);

function causesLookup(term: SpfTerm): boolean {
  return term.kind === "mechanism" ? LOOKUP_MECHANISMS.has(term.name) : term.name === "redirect";
}

/** redirect= is ignored when the record has an `all` mechanism (RFC 7208 §6.1). */
function followsRedirect(terms: SpfTerm[]): SpfTerm | undefined {
  if (terms.some((t) => t.kind === "mechanism" && t.name === "all")) return undefined;
  return terms.find((t) => t.kind === "modifier" && t.name === "redirect");
}

interface SpfWalkState {
  lookups: number;
  visited: Set<string>;
  warnings: string[];
  /** SPF records fetched for include/redirect targets, by domain. */
  records: Map<string, string>;
}

async function walkSpf(deps: EmailDeps, record: string, state: SpfWalkState, depth: number): Promise<void> {
  const terms = parseSpfTerms(record);
  const redirect = followsRedirect(terms);

  for (const term of terms) {
    if (term.kind === "modifier" && term !== redirect) continue;
    if (!causesLookup(term)) continue;

    state.lookups += 1;
    if (state.lookups > SPF_LOOKUP_LIMIT) return; // evaluation would already have failed

    const followable = term.name === "include" || term.name === "redirect";
    if (!followable || !term.value) continue;
    if (term.value.includes("%")) {
      state.warnings.push(`${term.name}:${term.value} uses SPF macros and was not followed.`);
      continue;
    }

    const target = term.value.toLowerCase();
    if (state.visited.has(target)) {
      state.warnings.push(`${target} is referenced more than once (possible loop) and was not followed again.`);
      continue;
    }
    state.visited.add(target);

    let spf: string[];
    try {
      spf = findSpfRecords(await lookupTxt(deps, target));
    } catch (err) {
      state.warnings.push((err as Error).message);
      continue;
    }
    if (spf.length !== 1) {
      state.warnings.push(
        spf.length === 0
          ? `${target} (via ${term.name}) has no SPF record, which makes SPF evaluation fail.`
          : `${target} (via ${term.name}) has multiple SPF records, which makes SPF evaluation fail.`
      );
      continue;
    }
    state.records.set(target, spf[0]!);
    if (depth < MAX_SPF_DEPTH) await walkSpf(deps, spf[0]!, state, depth + 1);
  }
}

function allQualifierOf(record: string): SpfQualifier | null {
  const all = parseSpfTerms(record).find((t) => t.kind === "mechanism" && t.name === "all");
  return all ? all.qualifier : null;
}

async function analyzeSpf(deps: EmailDeps, hostname: string, rootTxt: string[]): Promise<SpfAnalysis> {
  const records = findSpfRecords(rootTxt);
  const base: SpfAnalysis = {
    record: null,
    recordCount: records.length,
    allQualifier: null,
    redirect: null,
    dnsLookups: 0,
    lookupLimitExceeded: false,
    includes: [],
    warnings: [],
  };
  if (records.length !== 1) return base;

  const record = records[0]!.trim();
  const terms = parseSpfTerms(record);
  const redirect = followsRedirect(terms)?.value?.toLowerCase() ?? null;
  const state: SpfWalkState = { lookups: 0, visited: new Set([hostname]), warnings: [], records: new Map() };
  await walkSpf(deps, record, state, 0);

  // Without its own `all`, a record's default comes from its redirect target.
  let allQualifier = allQualifierOf(record);
  if (allQualifier === null && redirect && state.records.has(redirect)) {
    allQualifier = allQualifierOf(state.records.get(redirect)!);
  }

  return {
    ...base,
    record,
    allQualifier,
    redirect,
    dnsLookups: Math.min(state.lookups, SPF_LOOKUP_LIMIT + 1),
    lookupLimitExceeded: state.lookups > SPF_LOOKUP_LIMIT,
    includes: terms.filter((t) => t.kind === "mechanism" && t.name === "include" && t.value).map((t) => t.value!),
    warnings: state.warnings,
  };
}

// --- DMARC ------------------------------------------------------------------

function findDmarcRecords(txt: string[]): string[] {
  return txt.filter((record) => /^v\s*=\s*DMARC1\s*(;|$)/i.test(record.trim()));
}

function parsePolicy(value: string | undefined): DmarcPolicy | null {
  const v = value?.trim().toLowerCase();
  return v === "none" || v === "quarantine" || v === "reject" ? v : null;
}

export function parseDmarc(record: string): Pick<DmarcAnalysis, "valid" | "policy" | "subdomainPolicy" | "pct" | "reportingUris"> {
  const tags = new Map<string, string>();
  for (const part of record.split(";")) {
    const eq = part.indexOf("=");
    if (eq === -1) continue;
    tags.set(part.slice(0, eq).trim().toLowerCase(), part.slice(eq + 1).trim());
  }
  const policy = parsePolicy(tags.get("p"));
  const pctRaw = Number.parseInt(tags.get("pct") ?? "", 10);
  return {
    valid: policy !== null,
    policy,
    subdomainPolicy: parsePolicy(tags.get("sp")),
    pct: Number.isInteger(pctRaw) && pctRaw >= 0 && pctRaw <= 100 ? pctRaw : 100,
    reportingUris: (tags.get("rua") ?? "")
      .split(",")
      .map((uri) => uri.trim())
      .filter(Boolean),
  };
}

async function analyzeDmarc(deps: EmailDeps, hostname: string, organizationalDomain: string): Promise<DmarcAnalysis> {
  let foundAt = `_dmarc.${hostname}`;
  let records = findDmarcRecords(await lookupTxt(deps, foundAt));
  let inherited = false;

  // RFC 7489 §6.6.3: with no record at the exact name, fall back to the organizational domain.
  if (records.length === 0 && organizationalDomain !== hostname) {
    foundAt = `_dmarc.${organizationalDomain}`;
    records = findDmarcRecords(await lookupTxt(deps, foundAt));
    inherited = true;
  }

  const empty: DmarcAnalysis = {
    record: null,
    foundAt: null,
    inherited: false,
    recordCount: records.length,
    valid: false,
    policy: null,
    subdomainPolicy: null,
    effectivePolicy: null,
    pct: 100,
    reportingUris: [],
  };
  // Multiple records mean no policy applies at all (RFC 7489 §6.6.3).
  if (records.length !== 1) return { ...empty, foundAt: records.length > 1 ? foundAt : null, inherited: records.length > 1 && inherited };

  const record = records[0]!.trim();
  const parsed = parseDmarc(record);
  return {
    ...empty,
    ...parsed,
    record,
    foundAt,
    inherited,
    effectivePolicy: parsed.valid ? (inherited ? parsed.subdomainPolicy ?? parsed.policy : parsed.policy) : null,
  };
}

// --- MTA-STS / TLS-RPT ----------------------------------------------------------

export function parseMtaStsPolicy(body: string): { version: string | null; mode: MtaStsAnalysis["policyMode"]; maxAge: number | null } {
  const fields = new Map<string, string>();
  for (const line of body.split(/\r?\n/)) {
    const colon = line.indexOf(":");
    if (colon === -1) continue;
    fields.set(line.slice(0, colon).trim().toLowerCase(), line.slice(colon + 1).trim());
  }
  const mode = fields.get("mode")?.toLowerCase();
  const maxAge = Number.parseInt(fields.get("max_age") ?? "", 10);
  return {
    version: fields.get("version") ?? null,
    mode: mode === "enforce" || mode === "testing" || mode === "none" ? mode : null,
    maxAge: Number.isInteger(maxAge) && maxAge >= 0 ? maxAge : null,
  };
}

async function analyzeMtaSts(deps: EmailDeps, hostname: string, txt: string[]): Promise<MtaStsAnalysis> {
  const record = txt.find((r) => /^v=STSv1(\s*;|$)/i.test(r.trim()))?.trim() ?? null;
  const result: MtaStsAnalysis = { record, policyMode: null, policyMaxAge: null, policyError: null };
  if (!record) return result;

  try {
    const res = await deps.fetchText(`https://mta-sts.${hostname}/.well-known/mta-sts.txt`);
    if (res.statusCode !== 200) {
      return { ...result, policyError: `Policy endpoint returned HTTP ${res.statusCode}.` };
    }
    const policy = parseMtaStsPolicy(res.body);
    if (policy.version !== "STSv1" || policy.mode === null) {
      return { ...result, policyError: "Policy file is missing a valid version or mode." };
    }
    return { ...result, policyMode: policy.mode, policyMaxAge: policy.maxAge };
  } catch (err) {
    return { ...result, policyError: `Policy could not be fetched: ${(err as Error).message}` };
  }
}

// --- Entry point ---------------------------------------------------------------

/**
 * Passive email-authentication posture from DNS: SPF (including the
 * 10-lookup limit across include chains), DMARC (with organizational-domain
 * fallback), MTA-STS (TXT record and policy file), and TLS-RPT. DKIM is not
 * checked: its records live under sender-chosen selectors that can't be
 * discovered from DNS.
 */
export async function analyzeEmailSecurity(hostname: string, deps: EmailDeps = defaultDeps): Promise<ProviderResult<EmailSecurityInfo>> {
  const organizationalDomain = getRegistrableDomain(hostname);
  try {
    const [mx, rootTxt, mtaStsTxt, tlsRptTxt] = await Promise.all([
      lookupMx(deps, hostname),
      lookupTxt(deps, hostname),
      lookupTxt(deps, `_mta-sts.${hostname}`),
      lookupTxt(deps, `_smtp._tls.${hostname}`),
    ]);
    const [spf, dmarc, mtaSts] = await Promise.all([
      analyzeSpf(deps, hostname, rootTxt),
      analyzeDmarc(deps, hostname, organizationalDomain),
      analyzeMtaSts(deps, hostname, mtaStsTxt),
    ]);

    return {
      status: "ok",
      data: {
        domain: hostname,
        organizationalDomain,
        // A "null MX" (RFC 7505: a single "." exchange) explicitly declares that the domain accepts no mail.
        receivesMail: mx.some((record) => record.exchange !== "" && record.exchange !== "."),
        spf,
        dmarc,
        mtaSts,
        tlsRptRecord: tlsRptTxt.find((r) => /^v=TLSRPTv1(\s*;|$)/i.test(r.trim()))?.trim() ?? null,
      },
    };
  } catch (err) {
    return { status: "error", message: `Email security lookup failed: ${(err as Error).message}` };
  }
}

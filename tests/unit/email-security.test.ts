import { describe, expect, it, vi } from "vitest";
import {
  SPF_LOOKUP_LIMIT,
  analyzeEmailSecurity,
  parseDmarc,
  parseMtaStsPolicy,
  parseSpfTerms,
  type EmailDeps,
} from "@/services/email";

const noRecord = (name: string) => Object.assign(new Error(`queryTxt ENODATA ${name}`), { code: "ENODATA" });

interface FakeZone {
  txt?: Record<string, string[]>;
  mx?: Record<string, { priority: number; exchange: string }[]>;
  servfail?: string[];
  policies?: Record<string, { statusCode: number; body: string } | Error>;
}

/** In-memory DNS + HTTP for the email service; unknown names have no records. */
function fakeDeps(zone: FakeZone): EmailDeps & { txtQueries: string[]; fetched: string[] } {
  const txtQueries: string[] = [];
  const fetched: string[] = [];
  return {
    txtQueries,
    fetched,
    async resolveTxt(name) {
      txtQueries.push(name);
      if (zone.servfail?.includes(name)) throw Object.assign(new Error(`queryTxt ESERVFAIL ${name}`), { code: "ESERVFAIL" });
      const records = zone.txt?.[name];
      if (!records) throw noRecord(name);
      return records.map((r) => [r]);
    },
    async resolveMx(name) {
      const records = zone.mx?.[name];
      if (!records) throw noRecord(name);
      return records;
    },
    async fetchText(url) {
      fetched.push(url);
      const policy = zone.policies?.[url];
      if (!policy) return { statusCode: 404, body: "" };
      if (policy instanceof Error) throw policy;
      return policy;
    },
  };
}

const MAIL = { "example.com": [{ priority: 10, exchange: "mx.example.com" }] };

async function analyze(hostname: string, zone: FakeZone) {
  const deps = fakeDeps(zone);
  const result = await analyzeEmailSecurity(hostname, deps);
  if (result.status !== "ok" || !result.data) throw new Error(`expected ok, got ${result.status}: ${result.message}`);
  return { data: result.data, deps };
}

describe("parseSpfTerms", () => {
  it("parses qualifiers, mechanisms, arguments and modifiers", () => {
    const terms = parseSpfTerms("v=spf1 ip4:192.0.2.0/24 a/24 -include:_spf.example.net ~all redirect=other.example");
    expect(terms).toEqual([
      { kind: "mechanism", qualifier: "+", name: "ip4", value: "192.0.2.0" },
      { kind: "mechanism", qualifier: "+", name: "a", value: null },
      { kind: "mechanism", qualifier: "-", name: "include", value: "_spf.example.net" },
      { kind: "mechanism", qualifier: "~", name: "all", value: null },
      { kind: "modifier", qualifier: "+", name: "redirect", value: "other.example" },
    ]);
  });
});

describe("parseDmarc", () => {
  it("reads policy, subdomain policy, pct and report URIs", () => {
    expect(parseDmarc("v=DMARC1; p=quarantine; sp=reject; pct=50; rua=mailto:a@example.com, mailto:b@example.com")).toEqual({
      valid: true,
      policy: "quarantine",
      subdomainPolicy: "reject",
      pct: 50,
      reportingUris: ["mailto:a@example.com", "mailto:b@example.com"],
    });
  });

  it("treats a missing or unknown p= as invalid and defaults pct to 100", () => {
    expect(parseDmarc("v=DMARC1; rua=mailto:a@example.com")).toMatchObject({ valid: false, policy: null, pct: 100 });
    expect(parseDmarc("v=DMARC1; p=block; pct=900")).toMatchObject({ valid: false, pct: 100 });
  });
});

describe("parseMtaStsPolicy", () => {
  it("reads version, mode and max_age", () => {
    expect(parseMtaStsPolicy("version: STSv1\r\nmode: enforce\r\nmx: mx.example.com\r\nmax_age: 604800\r\n")).toEqual({
      version: "STSv1",
      mode: "enforce",
      maxAge: 604800,
    });
  });
});

describe("analyzeEmailSecurity — SPF", () => {
  it("reports the record, its all qualifier and top-level includes", async () => {
    const { data } = await analyze("example.com", {
      mx: MAIL,
      txt: {
        "example.com": ["v=spf1 include:_spf.example.net -all", "google-site-verification=abc"],
        "_spf.example.net": ["v=spf1 ip4:192.0.2.0/24 -all"],
      },
    });
    expect(data.receivesMail).toBe(true);
    expect(data.spf).toMatchObject({
      record: "v=spf1 include:_spf.example.net -all",
      recordCount: 1,
      allQualifier: "-",
      includes: ["_spf.example.net"],
      dnsLookups: 1,
      lookupLimitExceeded: false,
      warnings: [],
    });
  });

  it("counts DNS-querying terms through nested includes", async () => {
    const { data } = await analyze("example.com", {
      txt: {
        "example.com": ["v=spf1 mx a include:one.example -all"],
        "one.example": ["v=spf1 include:two.example exists:%{i}.x.example ~all"],
        "two.example": ["v=spf1 a:host.example -all"],
      },
    });
    // mx, a, include:one | include:two, exists | a:host
    expect(data.spf.dnsLookups).toBe(6);
  });

  it("flags a record that needs more than 10 lookups", async () => {
    const includes = Array.from({ length: SPF_LOOKUP_LIMIT + 1 }, (_, i) => `include:i${i}.example`).join(" ");
    const txt: Record<string, string[]> = { "example.com": [`v=spf1 ${includes} -all`] };
    for (let i = 0; i <= SPF_LOOKUP_LIMIT; i++) txt[`i${i}.example`] = ["v=spf1 ip4:192.0.2.1 -all"];
    const { data, deps } = await analyze("example.com", { txt });
    expect(data.spf.lookupLimitExceeded).toBe(true);
    expect(data.spf.dnsLookups).toBe(SPF_LOOKUP_LIMIT + 1);
    // Stops following once over the limit instead of resolving everything.
    expect(deps.txtQueries.filter((q) => q.startsWith("i"))).toHaveLength(SPF_LOOKUP_LIMIT);
  });

  it("detects an include cycle back to the domain itself instead of following it", async () => {
    const { data } = await analyze("example.com", {
      txt: {
        "example.com": ["v=spf1 include:a.example -all"],
        "a.example": ["v=spf1 include:example.com -all"],
      },
    });
    expect(data.spf.warnings).toEqual([expect.stringMatching(/^example\.com is referenced more than once/)]);
    expect(data.spf.dnsLookups).toBe(2);
  });

  it("warns when an include target has no SPF record", async () => {
    const { data } = await analyze("example.com", { txt: { "example.com": ["v=spf1 include:missing.example -all"] } });
    expect(data.spf.warnings).toEqual([expect.stringMatching(/missing\.example .*no SPF record/)]);
  });

  it("takes the all qualifier from a redirect= target when the record has none", async () => {
    const { data } = await analyze("example.com", {
      txt: { "example.com": ["v=spf1 redirect=_spf.example.net"], "_spf.example.net": ["v=spf1 ip4:192.0.2.1 -all"] },
    });
    expect(data.spf).toMatchObject({ redirect: "_spf.example.net", allQualifier: "-", dnsLookups: 1 });
  });

  it("reports multiple SPF records without picking one", async () => {
    const { data } = await analyze("example.com", { txt: { "example.com": ["v=spf1 -all", "v=spf1 +all"] } });
    expect(data.spf).toMatchObject({ record: null, recordCount: 2 });
  });

  it("returns an error — not 'no SPF' — when the resolver fails", async () => {
    const result = await analyzeEmailSecurity("example.com", fakeDeps({ mx: MAIL, servfail: ["example.com"] }));
    expect(result.status).toBe("error");
    expect(result.message).toMatch(/ESERVFAIL/);
  });
});

describe("analyzeEmailSecurity — DMARC", () => {
  it("uses the record published at the hostname", async () => {
    const { data } = await analyze("example.com", { txt: { "_dmarc.example.com": ["v=DMARC1; p=reject"] } });
    expect(data.dmarc).toMatchObject({ foundAt: "_dmarc.example.com", inherited: false, policy: "reject", effectivePolicy: "reject" });
  });

  it("falls back to the organizational domain and applies its sp= policy", async () => {
    const { data } = await analyze("mail.example.com", {
      txt: { "_dmarc.example.com": ["v=DMARC1; p=reject; sp=quarantine"] },
    });
    expect(data.organizationalDomain).toBe("example.com");
    expect(data.dmarc).toMatchObject({ foundAt: "_dmarc.example.com", inherited: true, effectivePolicy: "quarantine" });
  });

  it("reports no policy when there are multiple DMARC records", async () => {
    const { data } = await analyze("example.com", { txt: { "_dmarc.example.com": ["v=DMARC1; p=reject", "v=DMARC1; p=none"] } });
    expect(data.dmarc).toMatchObject({ record: null, recordCount: 2, effectivePolicy: null });
  });

  it("reports nothing when no DMARC record exists anywhere", async () => {
    const { data } = await analyze("www.example.com", {});
    expect(data.dmarc).toMatchObject({ record: null, recordCount: 0, foundAt: null });
  });
});

describe("analyzeEmailSecurity — MTA-STS, TLS-RPT and MX", () => {
  const POLICY_URL = "https://mta-sts.example.com/.well-known/mta-sts.txt";

  it("fetches and parses the policy when the TXT record exists", async () => {
    const { data } = await analyze("example.com", {
      txt: { "_mta-sts.example.com": ["v=STSv1; id=20260101"], "_smtp._tls.example.com": ["v=TLSRPTv1; rua=mailto:tls@example.com"] },
      policies: { [POLICY_URL]: { statusCode: 200, body: "version: STSv1\nmode: testing\nmx: mx.example.com\nmax_age: 86400\n" } },
    });
    expect(data.mtaSts).toEqual({ record: "v=STSv1; id=20260101", policyMode: "testing", policyMaxAge: 86400, policyError: null });
    expect(data.tlsRptRecord).toBe("v=TLSRPTv1; rua=mailto:tls@example.com");
  });

  it("explains why an advertised policy could not be used", async () => {
    const missing = await analyze("example.com", { txt: { "_mta-sts.example.com": ["v=STSv1; id=1"] } });
    expect(missing.data.mtaSts.policyError).toMatch(/HTTP 404/);

    const failing = await analyze("example.com", {
      txt: { "_mta-sts.example.com": ["v=STSv1; id=1"] },
      policies: { [POLICY_URL]: new Error("Too many redirects (> 0)") },
    });
    expect(failing.data.mtaSts.policyError).toMatch(/redirects/);
  });

  it("does not fetch a policy when no MTA-STS record is published", async () => {
    const { data, deps } = await analyze("example.com", {});
    expect(data.mtaSts.record).toBeNull();
    expect(deps.fetched).toEqual([]);
  });

  it("treats a null MX (RFC 7505) as not receiving mail", async () => {
    const { data } = await analyze("example.com", { mx: { "example.com": [{ priority: 0, exchange: "" }] } });
    expect(data.receivesMail).toBe(false);
  });

  it("uses the real resolver and SSRF-safe fetch by default", async () => {
    // Smoke test of the default wiring without touching the network.
    const dns = await import("node:dns");
    const spy = vi.spyOn(dns.promises, "resolveTxt").mockRejectedValue(noRecord("x"));
    vi.spyOn(dns.promises, "resolveMx").mockRejectedValue(noRecord("x"));
    const result = await analyzeEmailSecurity("example.com");
    expect(result.status).toBe("ok");
    expect(spy).toHaveBeenCalledWith("example.com");
    vi.restoreAllMocks();
  });
});

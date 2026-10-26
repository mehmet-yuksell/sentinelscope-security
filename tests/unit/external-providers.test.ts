import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Reverse DNS is a real lookup in services/ip; stub it so no test touches the network.
const reverseMock = vi.fn();
vi.mock("node:dns", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:dns")>();
  return { ...actual, promises: { ...actual.promises, reverse: (ip: string) => reverseMock(ip) } };
});

const { analyzeDomain } = await import("@/services/domain");
const { analyzeIp } = await import("@/services/ip");
const { analyzeThreatIntelligence } = await import("@/services/threat-intelligence");

const fetchMock = vi.fn();

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

beforeEach(() => {
  fetchMock.mockReset();
  reverseMock.mockReset().mockResolvedValue(["host.example.net"]);
  vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

describe("analyzeDomain (RDAP)", () => {
  it("extracts registrar, dates, nameservers, status and age", async () => {
    const created = new Date(Date.now() - 400 * 86_400_000).toISOString();
    fetchMock.mockResolvedValue(
      jsonResponse(200, {
        status: ["client transfer prohibited"],
        events: [
          { eventAction: "registration", eventDate: created },
          { eventAction: "expiration", eventDate: "2030-01-01T00:00:00Z" },
          { eventAction: "last changed", eventDate: "2026-01-01T00:00:00Z" },
        ],
        nameservers: [{ ldhName: "ns1.example.net" }, {}],
        entities: [{ roles: ["registrar"], vcardArray: ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Example Registrar"]]] }],
      })
    );

    const result = await analyzeDomain("example.com");
    expect(fetchMock).toHaveBeenCalledWith("https://rdap.org/domain/example.com", expect.any(Object));
    expect(result).toMatchObject({
      status: "ok",
      data: {
        domain: "example.com",
        registrar: "Example Registrar",
        createdDate: created,
        expiresDate: "2030-01-01T00:00:00Z",
        updatedDate: "2026-01-01T00:00:00Z",
        nameservers: ["ns1.example.net"],
        domainAgeDays: 400,
        status: ["client transfer prohibited"],
      },
    });
  });

  it("falls back to the registrar handle when there is no vCard name", async () => {
    fetchMock.mockResolvedValue(jsonResponse(200, { entities: [{ roles: ["registrar"], handle: "292" }] }));
    expect((await analyzeDomain("example.com")).data?.registrar).toBe("292");
  });

  it("reports 404, other HTTP errors and network failures as unavailable", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(404, {}));
    expect(await analyzeDomain("nope.example")).toMatchObject({ status: "unavailable", message: expect.stringMatching(/No RDAP record/) });

    fetchMock.mockResolvedValueOnce(jsonResponse(503, {}));
    expect(await analyzeDomain("example.com")).toMatchObject({ status: "unavailable", message: expect.stringMatching(/HTTP 503/) });

    fetchMock.mockRejectedValueOnce(new Error("aborted"));
    expect(await analyzeDomain("example.com")).toMatchObject({ status: "unavailable", message: expect.stringMatching(/aborted/) });
  });
});

describe("analyzeIp", () => {
  it("combines provider data with a real reverse lookup and the datacenter heuristic", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(200, { ip: "203.0.113.10", asn: "AS16509", org: "Amazon.com, Inc.", country_name: "Germany", country_code: "DE", city: "Frankfurt" })
    );
    const result = await analyzeIp("203.0.113.10");
    expect(result).toEqual({
      status: "ok",
      data: {
        ip: "203.0.113.10",
        asn: "AS16509",
        organization: "Amazon.com, Inc.",
        isp: "Amazon.com, Inc.",
        country: "Germany",
        countryCode: "DE",
        city: "Frankfurt",
        reverseDns: "host.example.net",
        isDatacenter: true,
      },
    });
  });

  it("leaves reverse DNS and the heuristic empty when there is nothing to base them on", async () => {
    reverseMock.mockRejectedValue(Object.assign(new Error("ENOTFOUND"), { code: "ENOTFOUND" }));
    fetchMock.mockResolvedValue(jsonResponse(200, { ip: "203.0.113.11" }));
    expect((await analyzeIp("203.0.113.11")).data).toMatchObject({ reverseDns: null, isDatacenter: null, organization: null });
  });

  it("reports provider errors, rate limits and network failures as unavailable", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, { error: true, reason: "RateLimited" }));
    expect(await analyzeIp("203.0.113.12")).toEqual({ status: "unavailable", message: "RateLimited" });

    fetchMock.mockResolvedValueOnce(jsonResponse(429, {}));
    expect(await analyzeIp("203.0.113.12")).toMatchObject({ status: "unavailable", message: expect.stringMatching(/HTTP 429/) });

    fetchMock.mockRejectedValueOnce(new Error("socket hang up"));
    expect(await analyzeIp("203.0.113.12")).toMatchObject({ status: "unavailable", message: expect.stringMatching(/socket hang up/) });
  });
});

describe("analyzeThreatIntelligence", () => {
  it("reports both providers as unavailable without API keys, making no requests", async () => {
    vi.stubEnv("VIRUSTOTAL_API_KEY", "");
    vi.stubEnv("ABUSEIPDB_API_KEY", "");
    const result = await analyzeThreatIntelligence("example.com", "domain", "203.0.113.1");
    expect(result.virustotal.status).toBe("unavailable");
    expect(result.abuseipdb.status).toBe("unavailable");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("reads VirusTotal analysis stats for a domain and AbuseIPDB data for its IP", async () => {
    vi.stubEnv("VIRUSTOTAL_API_KEY", "vt-test-key");
    vi.stubEnv("ABUSEIPDB_API_KEY", "abuse-test-key");
    fetchMock.mockImplementation(async (url: string) =>
      url.includes("virustotal")
        ? jsonResponse(200, { data: { attributes: { last_analysis_stats: { malicious: 2, suspicious: 1, harmless: 60, undetected: 10 } } } })
        : jsonResponse(200, { data: { abuseConfidenceScore: 35, totalReports: 4 } })
    );

    const result = await analyzeThreatIntelligence("example.com", "domain", "203.0.113.1");
    expect(result.virustotal).toEqual({
      status: "ok",
      data: { provider: "VirusTotal", malicious: 2, suspicious: 1, harmless: 60, totalEngines: 73, reportUrl: "https://www.virustotal.com/gui/domain/example.com" },
    });
    expect(result.abuseipdb.data).toMatchObject({ abuseConfidenceScore: 35, totalReports: 4, reportUrl: "https://www.abuseipdb.com/check/203.0.113.1" });

    const vtCall = fetchMock.mock.calls.find(([url]) => String(url).includes("virustotal"))!;
    expect(vtCall[0]).toBe("https://www.virustotal.com/api/v3/domains/example.com");
    expect(vtCall[1].headers).toMatchObject({ "x-apikey": "vt-test-key" });
  });

  it("uses the IP endpoint for IP targets", async () => {
    vi.stubEnv("VIRUSTOTAL_API_KEY", "k");
    vi.stubEnv("ABUSEIPDB_API_KEY", "");
    fetchMock.mockResolvedValue(jsonResponse(200, { data: { attributes: { last_analysis_stats: { malicious: 0 } } } }));
    const result = await analyzeThreatIntelligence("8.8.8.8", "ipv4", "8.8.8.8");
    expect(fetchMock.mock.calls[0]![0]).toBe("https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8");
    expect(result.virustotal.data?.reportUrl).toBe("https://www.virustotal.com/gui/ip-address/8.8.8.8");
  });

  it("maps auth failures, rate limits, bad payloads and missing IPs to explicit states", async () => {
    vi.stubEnv("VIRUSTOTAL_API_KEY", "k");
    vi.stubEnv("ABUSEIPDB_API_KEY", "k");

    fetchMock.mockResolvedValue(jsonResponse(401, {}));
    let result = await analyzeThreatIntelligence("example.com", "domain", "203.0.113.1");
    expect(result.virustotal.message).toMatch(/rejected the configured API key/);
    expect(result.abuseipdb.message).toMatch(/rejected the configured API key/);

    fetchMock.mockResolvedValue(jsonResponse(429, {}));
    result = await analyzeThreatIntelligence("example.com", "domain", "203.0.113.1");
    expect(result.virustotal.message).toMatch(/rate limit/);
    expect(result.abuseipdb.message).toMatch(/rate limit/);

    fetchMock.mockResolvedValue(jsonResponse(200, { unexpected: true }));
    result = await analyzeThreatIntelligence("example.com", "domain", "203.0.113.1");
    expect(result.virustotal).toMatchObject({ status: "error", message: expect.stringMatching(/analysis statistics/) });
    expect(result.abuseipdb).toMatchObject({ status: "error", message: expect.stringMatching(/empty/) });

    fetchMock.mockRejectedValue(new Error("ETIMEDOUT"));
    result = await analyzeThreatIntelligence("example.com", "domain", null);
    expect(result.virustotal).toMatchObject({ status: "error", message: "ETIMEDOUT" });
    expect(result.abuseipdb.status).toBe("not_applicable");
  });
});

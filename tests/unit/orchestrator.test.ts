import { beforeEach, describe, expect, it, vi } from "vitest";
import type { PipelineStageResult } from "@/types/analysis";

const mocks = vi.hoisted(() => ({
  analyzeDns: vi.fn(),
  analyzeEmailSecurity: vi.fn(),
  analyzeIp: vi.fn(),
  analyzeTls: vi.fn(),
  fetchTargetPage: vi.fn(),
  analyzeDomain: vi.fn(),
  analyzeThreatIntelligence: vi.fn(),
  resolveAndAssertPublic: vi.fn(),
}));

vi.mock("@/services/dns", () => ({ analyzeDns: mocks.analyzeDns }));
vi.mock("@/services/email", () => ({ analyzeEmailSecurity: mocks.analyzeEmailSecurity }));
vi.mock("@/services/ip", () => ({ analyzeIp: mocks.analyzeIp }));
vi.mock("@/services/tls", () => ({ analyzeTls: mocks.analyzeTls }));
vi.mock("@/services/domain", () => ({ analyzeDomain: mocks.analyzeDomain }));
vi.mock("@/services/threat-intelligence", () => ({ analyzeThreatIntelligence: mocks.analyzeThreatIntelligence }));
vi.mock("@/services/http", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/services/http")>()),
  fetchTargetPage: mocks.fetchTargetPage,
}));
vi.mock("@/lib/security/ssrf", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/lib/security/ssrf")>()),
  resolveAndAssertPublic: mocks.resolveAndAssertPublic,
}));

const { runAnalysis } = await import("@/services/orchestrator");
const { InvalidTargetError } = await import("@/lib/validation/target");

const UNAVAILABLE_TI = { virustotal: { status: "unavailable" }, abuseipdb: { status: "unavailable" } };
const PAGE = { statusCode: 200, headers: { server: "nginx" }, body: "<html></html>", finalUrl: "https://www.example.com/", redirectChain: [] };

beforeEach(() => {
  for (const mock of Object.values(mocks)) mock.mockReset();
  mocks.analyzeDns.mockResolvedValue({ status: "ok", data: { a: ["203.0.113.5"], aaaa: [], mx: [], ns: ["ns1", "ns2"], txt: [], cname: [], soa: null, caa: [], dmarcRecord: null } });
  mocks.analyzeEmailSecurity.mockResolvedValue({ status: "error", message: "not under test" });
  mocks.analyzeIp.mockResolvedValue({ status: "unavailable" });
  mocks.analyzeTls.mockResolvedValue({ status: "error", message: "not under test" });
  mocks.fetchTargetPage.mockResolvedValue(PAGE);
  mocks.analyzeDomain.mockResolvedValue({ status: "unavailable" });
  mocks.analyzeThreatIntelligence.mockResolvedValue(UNAVAILABLE_TI);
});

describe("runAnalysis", () => {
  it("runs every stage in order and reports each one as it finishes", async () => {
    const reported: PipelineStageResult[] = [];
    const result = await runAnalysis("https://www.example.com", { onStage: (s) => reported.push(s) });

    const order = ["validation", "dns", "email", "ip", "tls", "http", "technology", "domain", "threat_intelligence", "risk_engine"];
    expect(reported.map((s) => s.stage)).toEqual(order);
    expect(result.pipeline.map((s) => s.stage)).toEqual(order);
    expect(result).toMatchObject({ target: "https://www.example.com", targetKind: "url", hostname: "www.example.com" });
    expect(result.id).toMatch(/^[0-9a-f-]{36}$/);
    expect(result.technologies.map((t) => t.name)).toContain("nginx");
  });

  it("passes each service the right input", async () => {
    await runAnalysis("www.example.com");
    expect(mocks.analyzeEmailSecurity).toHaveBeenCalledWith("www.example.com");
    expect(mocks.analyzeIp).toHaveBeenCalledWith("203.0.113.5"); // first A record
    expect(mocks.analyzeTls).toHaveBeenCalledWith("www.example.com", 443);
    expect(mocks.analyzeDomain).toHaveBeenCalledWith("example.com"); // registered domain, not the subdomain
    expect(mocks.analyzeThreatIntelligence).toHaveBeenCalledWith("www.example.com", "domain", "203.0.113.5");
  });

  it("skips DNS, email and domain stages for an IP target", async () => {
    const result = await runAnalysis("8.8.8.8");
    const skipped = result.pipeline.filter((s) => s.status === "skipped").map((s) => s.stage);
    expect(skipped).toEqual(["dns", "email", "domain"]);
    expect(result.dns.status).toBe("not_applicable");
    expect(result.email?.status).toBe("not_applicable");
    expect(mocks.analyzeIp).toHaveBeenCalledWith("8.8.8.8");
  });

  it("records a throwing stage as failed and carries on with the rest", async () => {
    mocks.fetchTargetPage.mockRejectedValue(new Error("connection reset"));
    const result = await runAnalysis("example.com");

    expect(result.pipeline.find((s) => s.stage === "http")).toMatchObject({ status: "failed", error: "connection reset" });
    expect(result.pipeline.find((s) => s.stage === "technology")?.status).toBe("skipped");
    expect(result.http).toEqual({ status: "error", message: "HTTP analysis did not complete." });
    expect(result.pipeline.at(-1)).toMatchObject({ stage: "risk_engine", status: "success" });
  });

  it("falls back to an SSRF-checked lookup when DNS has no A record, and skips IP intel if that fails", async () => {
    mocks.analyzeDns.mockResolvedValue({ status: "error", message: "No DNS records" });
    mocks.resolveAndAssertPublic.mockRejectedValue(new Error("blocked"));
    const result = await runAnalysis("example.com");
    expect(result.pipeline.find((s) => s.stage === "ip")?.status).toBe("skipped");

    mocks.resolveAndAssertPublic.mockResolvedValue({ hostname: "example.com", addresses: ["203.0.113.9"] });
    await runAnalysis("example.com");
    expect(mocks.analyzeIp).toHaveBeenCalledWith("203.0.113.9");
  });

  it("rejects an invalid target before any network stage runs", async () => {
    await expect(runAnalysis("http://localhost")).rejects.toBeInstanceOf(InvalidTargetError);
    expect(mocks.analyzeDns).not.toHaveBeenCalled();
  });

  it("reports insufficient data when nothing could be measured", async () => {
    mocks.analyzeDns.mockResolvedValue({ status: "error" });
    mocks.fetchTargetPage.mockRejectedValue(new Error("down"));
    const result = await runAnalysis("example.com");
    expect(result.riskLevel).toBe("insufficient_data");
  });
});

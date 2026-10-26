import { beforeEach, describe, expect, it, vi } from "vitest";

const lookupMock = vi.fn();
vi.mock("node:dns", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:dns")>();
  return { ...actual, promises: { ...actual.promises, lookup: (...args: unknown[]) => lookupMock(...args) } };
});

const { SsrfBlockedError, assertSafePort, resolveAndAssertPublic } = await import("@/lib/security/ssrf");

beforeEach(() => lookupMock.mockReset());

describe("resolveAndAssertPublic", () => {
  it("returns every resolved address when all are public", async () => {
    lookupMock.mockResolvedValue([{ address: "93.184.216.34", family: 4 }, { address: "2606:4700::1111", family: 6 }]);
    expect(await resolveAndAssertPublic("Example.COM")).toEqual({ hostname: "example.com", addresses: ["93.184.216.34", "2606:4700::1111"] });
    expect(lookupMock).toHaveBeenCalledWith("example.com", { all: true, verbatim: true });
  });

  it("blocks a hostname if any one of its addresses is private (DNS rebinding with mixed answers)", async () => {
    lookupMock.mockResolvedValue([{ address: "8.8.8.8", family: 4 }, { address: "10.0.0.5", family: 4 }]);
    await expect(resolveAndAssertPublic("rebind.example")).rejects.toThrow(/non-public address 10\.0\.0\.5/);
  });

  it("checks IP literals directly without a DNS lookup", async () => {
    expect(await resolveAndAssertPublic("8.8.8.8")).toEqual({ hostname: "8.8.8.8", addresses: ["8.8.8.8"] });
    await expect(resolveAndAssertPublic("169.254.169.254")).rejects.toBeInstanceOf(SsrfBlockedError);
    expect(lookupMock).not.toHaveBeenCalled();
  });

  it("blocks reserved names before resolving them", async () => {
    for (const host of ["localhost", "metadata.google.internal", "printer.local", "db.internal"]) {
      await expect(resolveAndAssertPublic(host)).rejects.toThrow(/blocklisted or in a reserved TLD/);
    }
    expect(lookupMock).not.toHaveBeenCalled();
  });

  it("fails closed when resolution fails or returns nothing", async () => {
    lookupMock.mockRejectedValueOnce(new Error("getaddrinfo ENOTFOUND"));
    await expect(resolveAndAssertPublic("gone.example")).rejects.toThrow(/DNS resolution failed/);

    lookupMock.mockResolvedValueOnce([]);
    await expect(resolveAndAssertPublic("empty.example")).rejects.toThrow(/no addresses resolved/);
  });
});

describe("assertSafePort", () => {
  it("allows only 80 and 443", () => {
    expect(() => assertSafePort(80)).not.toThrow();
    expect(() => assertSafePort(443)).not.toThrow();
    expect(() => assertSafePort(8080)).toThrow(SsrfBlockedError);
  });
});

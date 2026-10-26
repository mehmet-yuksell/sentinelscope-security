import { beforeEach, describe, expect, it, vi } from "vitest";

const safeRequestMock = vi.fn();
vi.mock("@/lib/net/safeRequest", () => ({ safeRequest: (...args: unknown[]) => safeRequestMock(...args) }));

const { fetchTargetPage } = await import("@/services/http");

const OK = { statusCode: 200, headers: {}, body: "", finalUrl: "", redirectChain: [] };

beforeEach(() => safeRequestMock.mockReset());

describe("fetchTargetPage", () => {
  it("tries HTTPS first and stops at the first success", async () => {
    safeRequestMock.mockResolvedValue(OK);
    await fetchTargetPage("example.com", true);
    expect(safeRequestMock.mock.calls.map((c) => c[0])).toEqual(["https://example.com/"]);
  });

  it("falls back to HTTP when HTTPS fails", async () => {
    safeRequestMock.mockRejectedValueOnce(new Error("ECONNREFUSED")).mockResolvedValueOnce(OK);
    await fetchTargetPage("example.com", true);
    expect(safeRequestMock.mock.calls.map((c) => c[0])).toEqual(["https://example.com/", "http://example.com/"]);
  });

  it("tries HTTP first for explicit http:// targets", async () => {
    safeRequestMock.mockResolvedValue(OK);
    await fetchTargetPage("example.com", false);
    expect(safeRequestMock.mock.calls[0]![0]).toBe("http://example.com/");
  });

  it("throws the last error when every attempt fails", async () => {
    safeRequestMock.mockRejectedValueOnce(new Error("first")).mockRejectedValueOnce(new Error("second"));
    await expect(fetchTargetPage("example.com", true)).rejects.toThrow("second");
  });
});

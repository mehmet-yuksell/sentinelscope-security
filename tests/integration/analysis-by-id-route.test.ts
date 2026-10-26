import { describe, expect, it, vi } from "vitest";

const getAnalysisMock = vi.fn();
vi.mock("@/lib/store", () => ({ getAnalysis: (id: string) => getAnalysisMock(id) }));

const { GET } = await import("@/app/api/analysis/[id]/route");

function get(id: string) {
  return GET(new Request(`http://localhost/api/analysis/${id}`) as never, { params: Promise.resolve({ id }) });
}

describe("GET /api/analysis/[id]", () => {
  it("returns a stored analysis", async () => {
    getAnalysisMock.mockResolvedValue({ id: "abc", target: "example.com" });
    const res = await get("abc");
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ id: "abc", target: "example.com" });
    expect(getAnalysisMock).toHaveBeenCalledWith("abc");
  });

  it("returns 404 for an unknown id", async () => {
    getAnalysisMock.mockResolvedValue(null);
    const res = await get("nope");
    expect(res.status).toBe(404);
    expect(await res.json()).toEqual({ error: "Analysis not found." });
  });
});

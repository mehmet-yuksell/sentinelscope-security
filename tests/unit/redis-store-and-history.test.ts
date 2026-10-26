import { afterEach, describe, expect, it, vi } from "vitest";
import type { AnalysisResult, HistoryEntry } from "@/types/analysis";

const redisCalls: { set: unknown[][]; get: unknown[][] } = { set: [], get: [] };
const redisValues = new Map<string, unknown>();
vi.mock("@upstash/redis", () => ({
  Redis: class {
    async set(...args: unknown[]) {
      redisCalls.set.push(args);
      redisValues.set(args[0] as string, args[1]);
      return "OK";
    }
    async get(key: string) {
      redisCalls.get.push([key]);
      return redisValues.get(key) ?? null;
    }
  },
}));

const { createRedisStore } = await import("@/lib/store/redisStore");
const { addRecentAnalysis, getRecentAnalyses } = await import("@/utils/clientHistory");

describe("Redis store", () => {
  it("stores each analysis under its own key with a 30-day expiry and reads it back", async () => {
    const store = createRedisStore("https://redis.test", "token");
    const result = { id: "abc", target: "example.com" } as AnalysisResult;
    await store.saveAnalysis(result);

    expect(redisCalls.set[0]).toEqual(["sentinelscope:analysis:abc", result, { ex: 60 * 60 * 24 * 30 }]);
    expect(await store.getAnalysis("abc")).toEqual(result);
    expect(await store.getAnalysis("missing")).toBeNull();
  });
});

describe("client history (localStorage)", () => {
  afterEach(() => vi.unstubAllGlobals());

  function stubLocalStorage(initial: Record<string, string> = {}, { failWrites = false } = {}) {
    const data = new Map(Object.entries(initial));
    vi.stubGlobal("window", {
      localStorage: {
        getItem: (key: string) => data.get(key) ?? null,
        setItem: (key: string, value: string) => {
          if (failWrites) throw new Error("QuotaExceededError");
          data.set(key, value);
        },
      },
    });
    return data;
  }

  const entry = (id: string): HistoryEntry => ({ id, target: `${id}.example`, timestamp: "2026-01-01T00:00:00Z", riskScore: 10, riskLevel: "very_low" });

  it("returns nothing on the server, where there is no window", () => {
    expect(getRecentAnalyses()).toEqual([]);
    expect(() => addRecentAnalysis(entry("a"))).not.toThrow();
  });

  it("keeps the 8 most recent entries, newest first, without duplicates", () => {
    stubLocalStorage();
    for (let i = 0; i < 10; i++) addRecentAnalysis(entry(`e${i}`));
    addRecentAnalysis(entry("e5"));

    const ids = getRecentAnalyses().map((e) => e.id);
    expect(ids).toHaveLength(8);
    expect(ids[0]).toBe("e5");
    expect(ids.filter((id) => id === "e5")).toHaveLength(1);
  });

  it("ignores corrupt or non-array stored data", () => {
    stubLocalStorage({ "sentinelscope:recent-analyses": "{not json" });
    expect(getRecentAnalyses()).toEqual([]);
    stubLocalStorage({ "sentinelscope:recent-analyses": '{"id":"x"}' });
    expect(getRecentAnalyses()).toEqual([]);
  });

  it("silently skips saving when storage is unavailable", () => {
    stubLocalStorage({}, { failWrites: true });
    expect(() => addRecentAnalysis(entry("a"))).not.toThrow();
  });
});

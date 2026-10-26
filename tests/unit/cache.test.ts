import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { TtlCache } from "@/lib/cache";

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(new Date("2026-01-01T00:00:00Z"));
});

afterEach(() => {
  vi.useRealTimers();
});

describe("TtlCache", () => {
  it("returns a value until its TTL passes", () => {
    const cache = new TtlCache<string>(1_000);
    cache.set("k", "v");
    vi.advanceTimersByTime(1_000);
    expect(cache.get("k")).toBe("v");
    vi.advanceTimersByTime(1);
    expect(cache.get("k")).toBeUndefined();
    expect(cache.size).toBe(0);
  });

  it("deletes entries on request", () => {
    const cache = new TtlCache<string>(1_000);
    cache.set("k", "v");
    cache.delete("k");
    expect(cache.get("k")).toBeUndefined();
  });

  it("evicts the oldest entry when full", () => {
    const cache = new TtlCache<number>(60_000, 2);
    cache.set("a", 1);
    cache.set("b", 2);
    cache.set("c", 3);
    expect(cache.size).toBe(2);
    expect(cache.get("a")).toBeUndefined();
    expect(cache.get("c")).toBe(3);
  });

  it("sweeps expired entries before evicting live ones", () => {
    const cache = new TtlCache<number>(1_000, 2);
    cache.set("expired", 1);
    vi.advanceTimersByTime(1_001);
    cache.set("live", 2);
    cache.set("new", 3);
    expect(cache.get("live")).toBe(2);
    expect(cache.get("new")).toBe(3);
  });

  it("treats re-setting a key as most recent", () => {
    const cache = new TtlCache<number>(60_000, 2);
    cache.set("a", 1);
    cache.set("b", 2);
    cache.set("a", 10);
    cache.set("c", 3); // evicts "b", not the refreshed "a"
    expect(cache.get("a")).toBe(10);
    expect(cache.get("b")).toBeUndefined();
  });
});

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// A tiny in-memory stand-in for the Upstash REST client.
const redisData = new Map<string, { value: number; expiresAt: number | null }>();
const redisFailure = { error: null as Error | null };
vi.mock("@upstash/redis", () => ({
  Redis: class {
    async incr(key: string) {
      if (redisFailure.error) throw redisFailure.error;
      const entry = redisData.get(key) ?? { value: 0, expiresAt: null };
      entry.value += 1;
      redisData.set(key, entry);
      return entry.value;
    }
    async pexpire(key: string, ms: number) {
      const entry = redisData.get(key);
      if (entry) entry.expiresAt = Date.now() + ms;
      return 1;
    }
    async pttl(key: string) {
      const entry = redisData.get(key);
      return entry?.expiresAt ? entry.expiresAt - Date.now() : -1;
    }
  },
}));

const { FallbackRateLimiter, MemoryRateLimiter, RedisRateLimiter, getClientIp } = await import("@/lib/rateLimit");

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(new Date("2026-01-01T00:00:00Z"));
  redisData.clear();
  redisFailure.error = null;
});

afterEach(() => {
  vi.useRealTimers();
});

describe("MemoryRateLimiter", () => {
  it("allows up to max requests per window, then reports when to retry", async () => {
    const limiter = new MemoryRateLimiter(2, 60_000);
    expect(await limiter.check("ip")).toMatchObject({ allowed: true, remaining: 1 });
    expect(await limiter.check("ip")).toMatchObject({ allowed: true, remaining: 0 });

    vi.advanceTimersByTime(15_000);
    expect(await limiter.check("ip")).toEqual({ allowed: false, remaining: 0, retryAfterMs: 45_000 });
  });

  it("starts a fresh window once the old one ends, and keeps keys independent", async () => {
    const limiter = new MemoryRateLimiter(1, 60_000);
    await limiter.check("a");
    expect((await limiter.check("a")).allowed).toBe(false);
    expect((await limiter.check("b")).allowed).toBe(true);

    vi.advanceTimersByTime(60_000);
    expect((await limiter.check("a")).allowed).toBe(true);
  });

  it("never tracks more than maxTrackedKeys clients", async () => {
    const limiter = new MemoryRateLimiter(5, 60_000, 3);
    for (const ip of ["1", "2", "3", "4", "5"]) await limiter.check(ip);
    expect(limiter.trackedKeys).toBe(3);
  });

  it("sweeps expired buckets before evicting live ones", async () => {
    const limiter = new MemoryRateLimiter(1, 60_000, 2);
    await limiter.check("old");
    vi.advanceTimersByTime(60_000);
    await limiter.check("live");
    await limiter.check("new"); // full: "old" has expired and is swept, "live" stays
    expect((await limiter.check("live")).allowed).toBe(false);
  });
});

describe("RedisRateLimiter", () => {
  it("counts per key per window and sets an expiry on the first hit", async () => {
    const limiter = new RedisRateLimiter("https://redis.test", "token", 2, 60_000);
    expect(await limiter.check("ip")).toMatchObject({ allowed: true, remaining: 1 });
    expect(await limiter.check("ip")).toMatchObject({ allowed: true, remaining: 0 });

    const denied = await limiter.check("ip");
    expect(denied.allowed).toBe(false);
    expect(denied.retryAfterMs).toBeGreaterThan(0);
    expect(denied.retryAfterMs).toBeLessThanOrEqual(60_000);
    expect([...redisData.values()][0]!.expiresAt).not.toBeNull();
  });
});

describe("FallbackRateLimiter", () => {
  it("uses the primary limiter while it works", async () => {
    const fallback = new MemoryRateLimiter(1, 60_000);
    const limiter = new FallbackRateLimiter(new RedisRateLimiter("https://redis.test", "t", 5, 60_000), fallback);
    await limiter.check("ip");
    expect(fallback.trackedKeys).toBe(0);
  });

  it("falls back to the per-instance limiter instead of throwing when Redis fails", async () => {
    redisFailure.error = new Error("ECONNREFUSED");
    const limiter = new FallbackRateLimiter(new RedisRateLimiter("https://redis.test", "t", 5, 60_000), new MemoryRateLimiter(1, 60_000));
    expect((await limiter.check("ip")).allowed).toBe(true);
    expect((await limiter.check("ip")).allowed).toBe(false); // the fallback still limits
  });
});

describe("getClientIp", () => {
  it("uses the first X-Forwarded-For entry, then X-Real-IP, then 'unknown'", () => {
    expect(getClientIp(new Headers({ "x-forwarded-for": "203.0.113.5, 10.0.0.1" }))).toBe("203.0.113.5");
    expect(getClientIp(new Headers({ "x-real-ip": "203.0.113.6" }))).toBe("203.0.113.6");
    expect(getClientIp(new Headers())).toBe("unknown");
  });
});

interface Bucket {
  count: number;
  windowStart: number;
}

/**
 * Fixed-window in-memory rate limiter keyed by client IP. Good enough for a
 * single-instance deployment; a multi-instance deployment should back this
 * with Redis (INCR + EXPIRE) instead.
 */
export class RateLimiter {
  private buckets = new Map<string, Bucket>();

  constructor(
    private readonly max: number,
    private readonly windowMs: number
  ) {}

  check(key: string): { allowed: boolean; remaining: number; retryAfterMs: number } {
    const now = Date.now();
    const bucket = this.buckets.get(key);

    if (!bucket || now - bucket.windowStart >= this.windowMs) {
      this.buckets.set(key, { count: 1, windowStart: now });
      return { allowed: true, remaining: this.max - 1, retryAfterMs: 0 };
    }

    if (bucket.count >= this.max) {
      return { allowed: false, remaining: 0, retryAfterMs: this.windowMs - (now - bucket.windowStart) };
    }

    bucket.count += 1;
    return { allowed: true, remaining: this.max - bucket.count, retryAfterMs: 0 };
  }
}

export function getClientIp(headers: Headers): string {
  const forwardedFor = headers.get("x-forwarded-for");
  if (forwardedFor) return forwardedFor.split(",")[0]!.trim();
  return headers.get("x-real-ip") ?? "unknown";
}

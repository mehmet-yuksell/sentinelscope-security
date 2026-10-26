interface CacheEntry<T> {
  value: T;
  expiresAt: number;
}

const DEFAULT_MAX_ENTRIES = 500;

/**
 * Minimal in-memory TTL cache. Process-local by design — fine for a single
 * Next.js instance; swap for Redis if this ever runs multi-instance.
 *
 * Bounded: expired entries are swept when the cache is full, and if it is
 * still full the oldest entry is evicted, so a long-running process that sees
 * many distinct targets can't grow without limit.
 */
export class TtlCache<T> {
  private store = new Map<string, CacheEntry<T>>();

  constructor(
    private readonly ttlMs: number,
    private readonly maxEntries: number = DEFAULT_MAX_ENTRIES
  ) {}

  get size(): number {
    return this.store.size;
  }

  get(key: string): T | undefined {
    const entry = this.store.get(key);
    if (!entry) return undefined;
    if (Date.now() > entry.expiresAt) {
      this.store.delete(key);
      return undefined;
    }
    return entry.value;
  }

  set(key: string, value: T): void {
    // Re-inserting moves the key to the end of the Map's insertion order.
    this.store.delete(key);
    if (this.store.size >= this.maxEntries) this.makeRoom();
    this.store.set(key, { value, expiresAt: Date.now() + this.ttlMs });
  }

  delete(key: string): void {
    this.store.delete(key);
  }

  private makeRoom(): void {
    const now = Date.now();
    for (const [key, entry] of this.store) {
      if (now > entry.expiresAt) this.store.delete(key);
    }
    if (this.store.size >= this.maxEntries) {
      const oldest = this.store.keys().next().value;
      if (oldest !== undefined) this.store.delete(oldest);
    }
  }
}

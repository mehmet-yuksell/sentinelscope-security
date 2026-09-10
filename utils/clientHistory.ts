import type { HistoryEntry } from "@/types/analysis";

const STORAGE_KEY = "sentinelscope:recent-analyses";
const MAX_ENTRIES = 8;

/**
 * A visitor's "recent analyses" list lives ONLY in their own browser's
 * localStorage — it is never sent to or read from the server. Earlier this
 * was a server-side shared list, which meant every visitor could see every
 * other visitor's queried targets. Direct /analysis/[id] links remain
 * server-stored and shareable by design; the aggregate list must not be.
 */
export function getRecentAnalyses(): HistoryEntry[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

export function addRecentAnalysis(entry: HistoryEntry): void {
  if (typeof window === "undefined") return;
  try {
    const existing = getRecentAnalyses().filter((e) => e.id !== entry.id);
    const updated = [entry, ...existing].slice(0, MAX_ENTRIES);
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
  } catch {
    // Private browsing / storage disabled — recent-analyses is a
    // convenience feature, safe to silently no-op.
  }
}

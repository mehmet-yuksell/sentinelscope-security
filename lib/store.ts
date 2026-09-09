import { promises as fs } from "node:fs";
import path from "node:path";
import type { AnalysisResult, HistoryEntry } from "@/types/analysis";

const DATA_DIR = path.join(process.cwd(), "data");
const STORE_FILE = path.join(DATA_DIR, "analyses.json");
const MAX_ENTRIES = 200;

// Serializes writes so concurrent requests can't interleave file writes and
// corrupt the JSON store.
let writeQueue: Promise<unknown> = Promise.resolve();

async function ensureStore(): Promise<void> {
  await fs.mkdir(DATA_DIR, { recursive: true });
  try {
    await fs.access(STORE_FILE);
  } catch {
    await fs.writeFile(STORE_FILE, "[]", "utf-8");
  }
}

async function readAll(): Promise<AnalysisResult[]> {
  await ensureStore();
  try {
    const raw = await fs.readFile(STORE_FILE, "utf-8");
    return JSON.parse(raw) as AnalysisResult[];
  } catch {
    return [];
  }
}

async function writeAll(results: AnalysisResult[]): Promise<void> {
  await fs.writeFile(STORE_FILE, JSON.stringify(results.slice(0, MAX_ENTRIES), null, 2), "utf-8");
}

/**
 * Lightweight file-backed store for analysis history. Sufficient for a
 * single-instance deployment; swap for Postgres/SQLite if this needs to run
 * across multiple instances or survive container recreation without a
 * mounted volume.
 */
export async function saveAnalysis(result: AnalysisResult): Promise<void> {
  writeQueue = writeQueue.then(async () => {
    const all = await readAll();
    all.unshift(result);
    await writeAll(all);
  });
  await writeQueue;
}

export async function getAnalysis(id: string): Promise<AnalysisResult | null> {
  const all = await readAll();
  return all.find((r) => r.id === id) ?? null;
}

export async function listHistory(limit = 25): Promise<HistoryEntry[]> {
  const all = await readAll();
  return all.slice(0, limit).map((r) => ({
    id: r.id,
    target: r.target,
    timestamp: r.timestamp,
    riskScore: r.riskScore,
    riskLevel: r.riskLevel,
  }));
}

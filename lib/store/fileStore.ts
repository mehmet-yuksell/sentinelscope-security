import { promises as fs } from "node:fs";
import path from "node:path";
import type { AnalysisResult } from "@/types/analysis";
import type { AnalysisStore } from "./types";

const DATA_DIR = path.join(process.cwd(), "data");
const STORE_FILE = path.join(DATA_DIR, "analyses.json");
const MAX_ENTRIES = 200;

/**
 * File-backed store for a single, long-running Node process (local dev,
 * Docker, a VPS). Requires a writable, persistent filesystem shared across
 * every request — which serverless platforms like Vercel do NOT provide
 * (their function filesystem is read-only). Use createRedisStore() there
 * instead; this store degrades to "no history" rather than crashing if the
 * filesystem turns out not to be writable.
 */
export function createFileStore(): AnalysisStore {
  // Serializes writes so concurrent requests can't interleave file writes
  // and corrupt the JSON store.
  let writeQueue: Promise<unknown> = Promise.resolve();

  async function readAll(): Promise<AnalysisResult[]> {
    try {
      const raw = await fs.readFile(STORE_FILE, "utf-8");
      return JSON.parse(raw) as AnalysisResult[];
    } catch {
      return [];
    }
  }

  async function writeAll(results: AnalysisResult[]): Promise<void> {
    await fs.mkdir(DATA_DIR, { recursive: true });
    await fs.writeFile(STORE_FILE, JSON.stringify(results.slice(0, MAX_ENTRIES), null, 2), "utf-8");
  }

  return {
    async saveAnalysis(result) {
      writeQueue = writeQueue.then(async () => {
        const all = await readAll();
        all.unshift(result);
        await writeAll(all);
      });
      try {
        await writeQueue;
      } catch (err) {
        console.error("File store: could not persist analysis (read-only filesystem?):", (err as Error).message);
      }
    },

    async getAnalysis(id) {
      const all = await readAll();
      return all.find((r) => r.id === id) ?? null;
    },

    async listHistory(limit = 25) {
      const all = await readAll();
      return all.slice(0, limit).map((r) => ({
        id: r.id,
        target: r.target,
        timestamp: r.timestamp,
        riskScore: r.riskScore,
        riskLevel: r.riskLevel,
      }));
    },
  };
}

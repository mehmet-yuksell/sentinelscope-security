import { promises as fs } from "node:fs";
import path from "node:path";
import { errorFields, logger } from "@/lib/logger";
import type { AnalysisResult } from "@/types/analysis";
import type { AnalysisStore } from "./types";

const DEFAULT_DATA_DIR = path.join(process.cwd(), "data");
const MAX_ENTRIES = 200;

/**
 * File-backed store for a single, long-running Node process (local dev,
 * Docker, a VPS). Requires a writable, persistent filesystem shared across
 * every request — which serverless platforms like Vercel do NOT provide
 * (their function filesystem is read-only). Use createRedisStore() there
 * instead; this store degrades to "not persisted" rather than crashing if the
 * filesystem turns out not to be writable.
 */
export function createFileStore(dataDir: string = DEFAULT_DATA_DIR): AnalysisStore {
  const storeFile = path.join(dataDir, "analyses.json");

  // Serializes writes so concurrent requests can't interleave read-modify-write
  // cycles. The chain is kept alive with a no-op catch, so one failed write
  // doesn't make every later write fail too.
  let writeQueue: Promise<void> = Promise.resolve();

  /** A missing file is an empty store; an unreadable or corrupt one throws, so it is never overwritten. */
  async function readAll(): Promise<AnalysisResult[]> {
    let raw: string;
    try {
      raw = await fs.readFile(storeFile, "utf-8");
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw err;
    }
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed)) throw new Error(`${storeFile} does not contain a JSON array`);
    return parsed as AnalysisResult[];
  }

  /** Writes to a temp file and renames it into place, so a crash mid-write can't leave a truncated store. */
  async function writeAll(results: AnalysisResult[]): Promise<void> {
    await fs.mkdir(dataDir, { recursive: true });
    const tempFile = `${storeFile}.${process.pid}.tmp`;
    await fs.writeFile(tempFile, JSON.stringify(results.slice(0, MAX_ENTRIES), null, 2), "utf-8");
    await fs.rename(tempFile, storeFile);
  }

  return {
    async saveAnalysis(result) {
      const task = writeQueue.then(async () => {
        const all = await readAll();
        all.unshift(result);
        await writeAll(all);
      });
      writeQueue = task.catch(() => {});
      try {
        await task;
      } catch (err) {
        logger.error("store.persist_failed", { store: "file", analysisId: result.id, ...errorFields(err) });
      }
    },

    async getAnalysis(id) {
      const all = await readAll();
      return all.find((r) => r.id === id) ?? null;
    },
  };
}

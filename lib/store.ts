import { createFileStore } from "@/lib/store/fileStore";
import { createRedisStore } from "@/lib/store/redisStore";
import type { AnalysisStore } from "@/lib/store/types";

/**
 * Picks the storage backend at module load: Redis (Upstash) when its REST
 * credentials are configured — required on serverless platforms like Vercel
 * — otherwise the file-backed store used for local dev, Docker, and VPS
 * deployments. See lib/store/redisStore.ts and lib/store/fileStore.ts.
 */
function createStore(): AnalysisStore {
  const url = process.env.UPSTASH_REDIS_REST_URL ?? process.env.KV_REST_API_URL;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN ?? process.env.KV_REST_API_TOKEN;

  if (url && token) {
    return createRedisStore(url, token);
  }
  return createFileStore();
}

const store = createStore();

export const saveAnalysis = store.saveAnalysis;
export const getAnalysis = store.getAnalysis;
export const listHistory = store.listHistory;

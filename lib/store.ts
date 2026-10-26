import { getRedisCredentials } from "@/lib/redisConfig";
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
  const redis = getRedisCredentials();
  return redis ? createRedisStore(redis.url, redis.token) : createFileStore();
}

const store = createStore();

export const saveAnalysis = store.saveAnalysis;
export const getAnalysis = store.getAnalysis;

import { Redis } from "@upstash/redis";
import type { AnalysisResult } from "@/types/analysis";
import type { AnalysisStore } from "./types";

const ANALYSIS_TTL_SECONDS = 60 * 60 * 24 * 30; // 30 days — bounds storage on a free tier

function analysisKey(id: string): string {
  return `sentinelscope:analysis:${id}`;
}

/**
 * Redis-backed store (via Upstash's REST API, which works over plain fetch
 * and needs no persistent TCP connection) for serverless deployments like
 * Vercel, where every request may land on a different, stateless instance
 * and the local filesystem isn't shared or persistent.
 */
export function createRedisStore(url: string, token: string): AnalysisStore {
  const redis = new Redis({ url, token });

  return {
    async saveAnalysis(result) {
      await redis.set(analysisKey(result.id), result, { ex: ANALYSIS_TTL_SECONDS });
    },

    async getAnalysis(id) {
      const result = await redis.get<AnalysisResult>(analysisKey(id));
      return result ?? null;
    },
  };
}

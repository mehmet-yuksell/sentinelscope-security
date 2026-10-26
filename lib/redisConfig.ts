/**
 * Upstash Redis REST credentials, if configured. Accepts both Upstash's own
 * variable names and the KV_* names Vercel's Upstash integration injects.
 */
export function getRedisCredentials(): { url: string; token: string } | null {
  const url = process.env.UPSTASH_REDIS_REST_URL ?? process.env.KV_REST_API_URL;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN ?? process.env.KV_REST_API_TOKEN;
  return url && token ? { url, token } : null;
}

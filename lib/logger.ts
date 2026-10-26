/**
 * Minimal structured logger: one JSON object per line on stdout/stderr, which
 * Vercel, Docker and most log collectors index without extra parsing.
 *
 * Conventions:
 * - `event` is a stable dot-separated name (e.g. "store.persist_failed") so
 *   logs can be searched and alerted on.
 * - Never log API keys, tokens, request bodies, or analyzed targets — log ids,
 *   stage names and error messages instead.
 *
 * LOG_LEVEL selects the minimum level ("debug" | "info" | "warn" | "error" |
 * "silent"); the default is "info". Tests run with "silent".
 */

type Level = "debug" | "info" | "warn" | "error";

const LEVEL_ORDER: Record<Level | "silent", number> = { debug: 10, info: 20, warn: 30, error: 40, silent: 100 };

export type LogFields = Record<string, unknown>;

function minimumLevel(): number {
  const configured = (process.env.LOG_LEVEL ?? "info").toLowerCase();
  return LEVEL_ORDER[configured as Level | "silent"] ?? LEVEL_ORDER.info;
}

/** Serializable view of a thrown value; keeps the stack for server logs only. */
export function errorFields(err: unknown): { error: { name: string; message: string; stack?: string } } {
  if (err instanceof Error) return { error: { name: err.name, message: err.message, stack: err.stack } };
  return { error: { name: "NonError", message: String(err) } };
}

function write(level: Level, event: string, fields: LogFields): void {
  if (LEVEL_ORDER[level] < minimumLevel()) return;
  const line = JSON.stringify({ time: new Date().toISOString(), level, event, ...fields });
  if (level === "error") console.error(line);
  else if (level === "warn") console.warn(line);
  else console.log(line);
}

export const logger = {
  debug: (event: string, fields: LogFields = {}) => write("debug", event, fields),
  info: (event: string, fields: LogFields = {}) => write("info", event, fields),
  warn: (event: string, fields: LogFields = {}) => write("warn", event, fields),
  error: (event: string, fields: LogFields = {}) => write("error", event, fields),
};

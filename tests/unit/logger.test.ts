import { afterEach, describe, expect, it, vi } from "vitest";
import { errorFields, logger } from "@/lib/logger";

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
});

describe("logger", () => {
  it("writes one JSON line with time, level, event and fields", () => {
    vi.stubEnv("LOG_LEVEL", "info");
    const spy = vi.spyOn(console, "warn").mockImplementation(() => {});
    logger.warn("rate_limiter.fallback", { reason: "redis down" });

    expect(spy).toHaveBeenCalledTimes(1);
    const entry = JSON.parse(spy.mock.calls[0]![0] as string);
    expect(entry).toMatchObject({ level: "warn", event: "rate_limiter.fallback", reason: "redis down" });
    expect(new Date(entry.time).toString()).not.toBe("Invalid Date");
  });

  it("routes errors to stderr and info to stdout", () => {
    vi.stubEnv("LOG_LEVEL", "debug");
    const error = vi.spyOn(console, "error").mockImplementation(() => {});
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    logger.error("a");
    logger.info("b");
    logger.debug("c");
    expect(error).toHaveBeenCalledTimes(1);
    expect(log).toHaveBeenCalledTimes(2);
  });

  it("drops entries below LOG_LEVEL, and everything when silent", () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    const error = vi.spyOn(console, "error").mockImplementation(() => {});

    vi.stubEnv("LOG_LEVEL", "warn");
    logger.info("ignored");
    expect(log).not.toHaveBeenCalled();

    vi.stubEnv("LOG_LEVEL", "silent");
    logger.error("ignored too");
    expect(error).not.toHaveBeenCalled();
  });

  it("falls back to info for an unknown LOG_LEVEL", () => {
    vi.stubEnv("LOG_LEVEL", "verbose");
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    logger.debug("ignored");
    logger.info("kept");
    expect(log).toHaveBeenCalledTimes(1);
  });
});

describe("errorFields", () => {
  it("serializes Error instances and non-Error values", () => {
    expect(errorFields(new TypeError("bad"))).toMatchObject({ error: { name: "TypeError", message: "bad" } });
    expect(errorFields("plain string")).toEqual({ error: { name: "NonError", message: "plain string" } });
  });
});

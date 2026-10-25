import { describe, expect, it } from "vitest";
import { analyzeTls } from "@/services/tls";

describe("analyzeTls", () => {
  it("refuses to connect to a non-standard port, before any DNS or socket activity", async () => {
    const result = await analyzeTls("example.com", 22);
    expect(result.status).toBe("error");
    expect(result.message).toMatch(/ports 80 and 443/);
  });
});

import type { CaaRecord } from "node:dns";
import { describe, expect, it } from "vitest";
import { resolveCaaWithInheritance } from "@/services/dns";

const LETSENCRYPT: CaaRecord[] = [{ critical: 0, issue: "letsencrypt.org" }];

/** Builds a fake resolver from a zone map; any name not listed has no CAA (ENODATA). */
function fakeResolver(zone: Record<string, CaaRecord[]>) {
  const queried: string[] = [];
  const resolve = async (name: string) => {
    queried.push(name);
    const records = zone[name];
    if (!records) throw Object.assign(new Error(`queryCaa ENODATA ${name}`), { code: "ENODATA" });
    return records;
  };
  return { resolve, queried };
}

describe("resolveCaaWithInheritance", () => {
  it("returns the hostname's own CAA records when present", async () => {
    const { resolve } = fakeResolver({ "example.com": LETSENCRYPT });
    const result = await resolveCaaWithInheritance("example.com", resolve);
    expect(result).toEqual({ records: LETSENCRYPT, foundAt: "example.com" });
  });

  it("inherits CAA from a parent domain, as RFC 8659 requires", async () => {
    const { resolve, queried } = fakeResolver({ "example.com": LETSENCRYPT });
    const result = await resolveCaaWithInheritance("api.eu.example.com", resolve);
    expect(result).toEqual({ records: LETSENCRYPT, foundAt: "example.com" });
    expect(queried).toEqual(["api.eu.example.com", "eu.example.com", "example.com"]);
  });

  it("stops at the closest name that has CAA records", async () => {
    const own: CaaRecord[] = [{ critical: 0, issue: "digicert.com" }];
    const { resolve, queried } = fakeResolver({ "shop.example.com": own, "example.com": LETSENCRYPT });
    const result = await resolveCaaWithInheritance("shop.example.com", resolve);
    expect(result.foundAt).toBe("shop.example.com");
    expect(queried).toEqual(["shop.example.com"]);
  });

  it("reports no CAA when no name up the tree has any, without querying the bare TLD", async () => {
    const { resolve, queried } = fakeResolver({});
    const result = await resolveCaaWithInheritance("www.example.com", resolve);
    expect(result).toEqual({ records: [], foundAt: null });
    expect(queried).not.toContain("com");
  });
});

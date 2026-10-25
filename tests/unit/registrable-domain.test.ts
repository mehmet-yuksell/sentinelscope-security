import { describe, expect, it } from "vitest";
import { getRegistrableDomain } from "@/lib/dns/registrableDomain";

describe("getRegistrableDomain", () => {
  it("returns an apex domain unchanged", () => {
    expect(getRegistrableDomain("example.com")).toBe("example.com");
  });

  it("strips subdomains down to the registered domain", () => {
    expect(getRegistrableDomain("www.example.com")).toBe("example.com");
    expect(getRegistrableDomain("api.eu.example.com")).toBe("example.com");
  });

  it("understands multi-label public suffixes", () => {
    expect(getRegistrableDomain("shop.example.co.uk")).toBe("example.co.uk");
    expect(getRegistrableDomain("www.example.com.tr")).toBe("example.com.tr");
  });

  it("uses the ICANN section of the list, i.e. the domain a registrar actually holds", () => {
    // github.io is a *private* public suffix; its registration belongs to GitHub.
    expect(getRegistrableDomain("someone.github.io")).toBe("github.io");
  });

  it("falls back to the hostname when no registrable domain can be derived", () => {
    expect(getRegistrableDomain("co.uk")).toBe("co.uk");
  });
});

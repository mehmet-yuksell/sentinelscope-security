import { describe, expect, it } from "vitest";
import { InvalidTargetError, parseTarget } from "@/lib/validation/target";

describe("parseTarget", () => {
  it("parses a bare domain", () => {
    const target = parseTarget("example.com");
    expect(target).toMatchObject({ kind: "domain", hostname: "example.com", protocol: "https", port: 443 });
  });

  it("parses an https URL and preserves an explicit port", () => {
    const target = parseTarget("https://example.com:8443/path");
    expect(target).toMatchObject({ kind: "url", hostname: "example.com", protocol: "https", port: 8443 });
  });

  it("parses an http URL", () => {
    const target = parseTarget("http://example.com");
    expect(target).toMatchObject({ kind: "url", hostname: "example.com", protocol: "http", port: 80 });
  });

  it("parses a public IPv4 literal", () => {
    const target = parseTarget("8.8.8.8");
    expect(target).toMatchObject({ kind: "ipv4", hostname: "8.8.8.8" });
  });

  it("parses a public IPv6 literal", () => {
    const target = parseTarget("2001:4860:4860::8888");
    expect(target.kind).toBe("ipv6");
  });

  it("lowercases hostnames", () => {
    const target = parseTarget("ExAmple.COM");
    expect(target.hostname).toBe("example.com");
  });

  it("rejects an empty target", () => {
    expect(() => parseTarget("   ")).toThrow(InvalidTargetError);
  });

  it("rejects targets containing whitespace", () => {
    expect(() => parseTarget("example.com foo")).toThrow(InvalidTargetError);
  });

  it("rejects a malformed domain", () => {
    expect(() => parseTarget("not_a_domain")).toThrow(InvalidTargetError);
    expect(() => parseTarget("nodothost")).toThrow(InvalidTargetError);
  });

  it("rejects unsupported URL schemes", () => {
    expect(() => parseTarget("ftp://example.com")).toThrow(InvalidTargetError);
  });

  it("rejects URLs with embedded credentials", () => {
    expect(() => parseTarget("https://user:pass@example.com")).toThrow(InvalidTargetError);
  });

  it("rejects loopback IP literals", () => {
    expect(() => parseTarget("127.0.0.1")).toThrow(InvalidTargetError);
  });

  it("rejects private IPv4 literals", () => {
    expect(() => parseTarget("10.0.0.5")).toThrow(InvalidTargetError);
    expect(() => parseTarget("192.168.1.1")).toThrow(InvalidTargetError);
    expect(() => parseTarget("172.16.0.1")).toThrow(InvalidTargetError);
  });

  it("rejects cloud metadata address 169.254.169.254", () => {
    expect(() => parseTarget("169.254.169.254")).toThrow(InvalidTargetError);
  });

  it("rejects the localhost hostname and .local/.internal TLDs", () => {
    expect(() => parseTarget("localhost")).toThrow(InvalidTargetError);
    expect(() => parseTarget("printer.local")).toThrow(InvalidTargetError);
    expect(() => parseTarget("service.internal")).toThrow(InvalidTargetError);
  });
});

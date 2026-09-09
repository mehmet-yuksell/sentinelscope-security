import { describe, expect, it } from "vitest";
import { isReservedIp } from "@/lib/security/ssrf";

describe("isReservedIp", () => {
  it("flags IPv4 loopback", () => {
    expect(isReservedIp("127.0.0.1")).toBe(true);
    expect(isReservedIp("127.255.255.255")).toBe(true);
  });

  it("flags IPv4 private ranges (RFC1918)", () => {
    expect(isReservedIp("10.0.0.1")).toBe(true);
    expect(isReservedIp("172.16.0.1")).toBe(true);
    expect(isReservedIp("172.31.255.255")).toBe(true);
    expect(isReservedIp("192.168.0.1")).toBe(true);
  });

  it("does not flag addresses just outside the 172.16.0.0/12 range", () => {
    expect(isReservedIp("172.15.255.255")).toBe(false);
    expect(isReservedIp("172.32.0.1")).toBe(false);
  });

  it("flags link-local and cloud metadata (169.254.0.0/16)", () => {
    expect(isReservedIp("169.254.169.254")).toBe(true);
    expect(isReservedIp("169.254.1.1")).toBe(true);
  });

  it("flags carrier-grade NAT (100.64.0.0/10)", () => {
    expect(isReservedIp("100.64.0.1")).toBe(true);
    expect(isReservedIp("100.127.255.255")).toBe(true);
  });

  it("flags multicast and broadcast", () => {
    expect(isReservedIp("224.0.0.1")).toBe(true);
    expect(isReservedIp("255.255.255.255")).toBe(true);
  });

  it("does not flag well-known public IPv4 addresses", () => {
    expect(isReservedIp("8.8.8.8")).toBe(false);
    expect(isReservedIp("1.1.1.1")).toBe(false);
    expect(isReservedIp("93.184.216.34")).toBe(false);
  });

  it("flags IPv6 loopback and unspecified", () => {
    expect(isReservedIp("::1")).toBe(true);
    expect(isReservedIp("::")).toBe(true);
  });

  it("flags IPv6 unique-local and link-local", () => {
    expect(isReservedIp("fc00::1")).toBe(true);
    expect(isReservedIp("fe80::1")).toBe(true);
  });

  it("flags IPv4-mapped IPv6 addresses that wrap a private IPv4", () => {
    expect(isReservedIp("::ffff:192.168.1.1")).toBe(true);
  });

  it("does not flag a public IPv6 address", () => {
    expect(isReservedIp("2001:4860:4860::8888")).toBe(false);
  });

  it("treats an unparsable string as unsafe (fail closed)", () => {
    expect(isReservedIp("not-an-ip")).toBe(true);
  });
});

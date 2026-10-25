import { isIP } from "node:net";
import { promises as dns } from "node:dns";

/**
 * Blocks outbound requests to loopback, private, link-local, multicast,
 * reserved, and cloud-metadata address space. Every outbound fetch/socket
 * SentinelScope makes (initial target + each redirect hop) must pass
 * through resolveAndAssertPublic() first.
 */

const BLOCKED_HOSTNAMES = new Set([
  "localhost",
  "localhost.localdomain",
  "metadata.google.internal",
]);

interface CidrV4 {
  base: number;
  bits: number;
}

function ipv4ToInt(ip: string): number {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some((p) => Number.isNaN(p) || p < 0 || p > 255)) {
    throw new Error(`Invalid IPv4 address: ${ip}`);
  }
  return ((parts[0]! << 24) | (parts[1]! << 16) | (parts[2]! << 8) | parts[3]!) >>> 0;
}

function parseCidrV4(cidr: string): CidrV4 {
  const [ip, bitsStr] = cidr.split("/");
  return { base: ipv4ToInt(ip!), bits: Number(bitsStr) };
}

const RESERVED_V4_CIDRS = [
  "0.0.0.0/8", // "this" network
  "10.0.0.0/8", // RFC1918
  "100.64.0.0/10", // carrier-grade NAT
  "127.0.0.0/8", // loopback
  "169.254.0.0/16", // link-local (incl. 169.254.169.254 cloud metadata)
  "172.16.0.0/12", // RFC1918
  "192.0.0.0/24", // IETF protocol assignments
  "192.0.2.0/24", // TEST-NET-1
  "192.88.99.0/24", // deprecated 6to4 relay anycast
  "192.168.0.0/16", // RFC1918
  "198.18.0.0/15", // benchmarking
  "198.51.100.0/24", // TEST-NET-2
  "203.0.113.0/24", // TEST-NET-3
  "224.0.0.0/4", // multicast
  "240.0.0.0/4", // reserved
  "255.255.255.255/32", // broadcast
].map(parseCidrV4);

function isReservedV4(ip: string): boolean {
  const int = ipv4ToInt(ip);
  return RESERVED_V4_CIDRS.some(({ base, bits }) => {
    if (bits === 0) return true;
    const mask = bits === 32 ? 0xffffffff : (0xffffffff << (32 - bits)) >>> 0;
    return (int & mask) === (base & mask);
  });
}

function expandIpv6(ip: string): bigint {
  let addr = ip;
  // A trailing dotted-quad (::ffff:1.2.3.4, ::1.2.3.4, 64:ff9b::1.2.3.4,
  // 0:0:0:0:0:ffff:1.2.3.4) is the last 32 bits; rewrite it as two hex groups.
  const lastColon = addr.lastIndexOf(":");
  const trailing = addr.slice(lastColon + 1);
  if (trailing.includes(".")) {
    const v4 = ipv4ToInt(trailing);
    addr = `${addr.slice(0, lastColon + 1)}${(v4 >>> 16).toString(16)}:${(v4 & 0xffff).toString(16)}`;
  }
  const [head, tail] = addr.split("::");
  const headParts = head ? head.split(":").filter(Boolean) : [];
  const tailParts = tail ? tail.split(":").filter(Boolean) : [];
  const missing = 8 - headParts.length - tailParts.length;
  const allParts = [...headParts, ...Array(Math.max(missing, 0)).fill("0"), ...tailParts];
  let value = 0n;
  for (const part of allParts) {
    value = (value << 16n) | BigInt(parseInt(part || "0", 16));
  }
  return value;
}

function isInV6Range(value: bigint, prefixAddress: string, prefixBits: number): boolean {
  const start = expandIpv6(prefixAddress);
  const shift = 128n - BigInt(prefixBits);
  return (value >> shift) === (start >> shift);
}

const RESERVED_V6_PREFIXES: [string, number][] = [
  ["fc00::", 7], // unique local
  ["fe80::", 10], // link-local
  ["ff00::", 8], // multicast
  ["2001:db8::", 32], // documentation range
  ["64:ff9b::", 96], // NAT64 (can embed internal IPv4 space)
  ["100::", 64], // discard-only range
  // Transition mechanisms that embed an IPv4 address (possibly internal) in
  // the IPv6 address. All are deprecated or unused by real public sites.
  ["::", 96], // IPv4-compatible
  ["2002::", 16], // 6to4
  ["2001::", 32], // Teredo
];

function isReservedV6(ip: string): boolean {
  const normalized = ip.toLowerCase();
  if (normalized === "::1") return true; // loopback
  if (normalized === "::") return true; // unspecified
  let value: bigint;
  try {
    value = expandIpv6(normalized);
  } catch {
    return true; // fail closed on unparsable input
  }
  // IPv4-mapped (::ffff:0:0/96) addresses must be checked against the v4 rules too.
  if (isInV6Range(value, "::ffff:0:0", 96)) {
    const v4Int = Number(value & 0xffffffffn);
    const v4 = [
      (v4Int >>> 24) & 0xff,
      (v4Int >>> 16) & 0xff,
      (v4Int >>> 8) & 0xff,
      v4Int & 0xff,
    ].join(".");
    return isReservedV4(v4);
  }
  return RESERVED_V6_PREFIXES.some(([prefix, bits]) => isInV6Range(value, prefix, bits));
}

export function isReservedIp(ip: string): boolean {
  const version = isIP(ip);
  if (version === 4) return isReservedV4(ip);
  if (version === 6) return isReservedV6(ip);
  return true; // not a valid IP at all -> treat as unsafe
}

export class SsrfBlockedError extends Error {
  constructor(hostname: string, reason: string) {
    super(`Blocked target "${hostname}": ${reason}`);
    this.name = "SsrfBlockedError";
  }
}

export interface ResolvedHost {
  hostname: string;
  addresses: string[];
}

/**
 * Resolves a hostname (or validates a literal IP) and throws SsrfBlockedError
 * if it points at non-public address space. Call this before every outbound
 * connection, including each hop of an HTTP redirect chain.
 */
export async function resolveAndAssertPublic(hostname: string): Promise<ResolvedHost> {
  const lower = hostname.toLowerCase();
  if (BLOCKED_HOSTNAMES.has(lower) || lower.endsWith(".local") || lower.endsWith(".internal")) {
    throw new SsrfBlockedError(hostname, "hostname is blocklisted or in a reserved TLD");
  }

  const directVersion = isIP(lower);
  const addresses: string[] = [];

  if (directVersion) {
    addresses.push(lower);
  } else {
    let records;
    try {
      records = await dns.lookup(lower, { all: true, verbatim: true });
    } catch (err) {
      throw new SsrfBlockedError(hostname, `DNS resolution failed: ${(err as Error).message}`);
    }
    for (const record of records) {
      addresses.push(record.address);
    }
  }

  if (addresses.length === 0) {
    throw new SsrfBlockedError(hostname, "no addresses resolved");
  }

  for (const address of addresses) {
    if (isReservedIp(address)) {
      throw new SsrfBlockedError(hostname, `resolves to non-public address ${address}`);
    }
  }

  return { hostname: lower, addresses };
}

export function assertSafePort(port: number): void {
  const allowed = new Set([80, 443]);
  if (!allowed.has(port)) {
    throw new SsrfBlockedError(String(port), "only ports 80 and 443 are permitted");
  }
}

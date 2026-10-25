import { isIP } from "node:net";
import type { ParsedTarget } from "@/types/analysis";
import { isReservedIp } from "@/lib/security/ssrf";

export class InvalidTargetError extends Error {}

// Conservative hostname/label shape check (RFC 1035-ish), not a full IDN parser.
const DOMAIN_REGEX = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;

function assertPublicHostname(hostname: string): void {
  const ipVersion = isIP(hostname);
  if (ipVersion) {
    if (isReservedIp(hostname)) {
      throw new InvalidTargetError("Private, loopback, and reserved IP addresses cannot be analyzed.");
    }
    return;
  }
  if (!DOMAIN_REGEX.test(hostname)) {
    throw new InvalidTargetError(`"${hostname}" is not a valid domain name.`);
  }
  if (hostname === "localhost" || hostname.endsWith(".local") || hostname.endsWith(".internal")) {
    throw new InvalidTargetError("Local and internal hostnames cannot be analyzed.");
  }
}

/**
 * Parses free-form user input (bare domain, full URL, or IP literal) into a
 * normalized target. This performs syntactic/literal validation only —
 * DNS-resolution-based SSRF checks happen later in resolveAndAssertPublic()
 * at request time, since a hostname's resolved IP can change between calls.
 */
export function parseTarget(raw: string): ParsedTarget {
  const input = raw.trim();
  if (!input) {
    throw new InvalidTargetError("Target must not be empty.");
  }
  if (input.length > 2048) {
    throw new InvalidTargetError("Target is too long.");
  }
  if (/\s/.test(input)) {
    throw new InvalidTargetError("Target must not contain whitespace.");
  }

  const ipVersion = isIP(input);
  if (ipVersion) {
    if (isReservedIp(input)) {
      throw new InvalidTargetError("Private, loopback, and reserved IP addresses cannot be analyzed.");
    }
    return {
      raw: input,
      kind: ipVersion === 4 ? "ipv4" : "ipv6",
      hostname: input,
      protocol: "https",
      port: 443,
      displayName: input,
    };
  }

  if (/^https?:\/\//i.test(input)) {
    let url: URL;
    try {
      url = new URL(input);
    } catch {
      throw new InvalidTargetError("Could not parse the provided URL.");
    }
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      throw new InvalidTargetError("Only http and https URLs are supported.");
    }
    if (url.username || url.password) {
      throw new InvalidTargetError("URLs with embedded credentials are not permitted.");
    }
    const hostname = url.hostname.toLowerCase();
    assertPublicHostname(hostname);
    const port = url.port ? Number(url.port) : url.protocol === "https:" ? 443 : 80;
    // Same rule safeRequest enforces per hop; checked here too because the TLS
    // stage would otherwise open a socket to whatever port the URL names.
    if (port !== 80 && port !== 443) {
      throw new InvalidTargetError("Only ports 80 and 443 can be analyzed.");
    }
    return {
      raw: input,
      kind: "url",
      hostname,
      protocol: url.protocol === "https:" ? "https" : "http",
      port,
      displayName: hostname,
    };
  }

  if (input.includes("://")) {
    throw new InvalidTargetError("Only http and https schemes are supported.");
  }

  const hostname = input.toLowerCase().replace(/\/+$/, "");
  assertPublicHostname(hostname);
  return {
    raw: input,
    kind: "domain",
    hostname,
    protocol: "https",
    port: 443,
    displayName: hostname,
  };
}

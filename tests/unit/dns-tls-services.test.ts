import { EventEmitter } from "node:events";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// --- DNS: the record lookups in services/dns are replaced by an in-memory zone.
const zone: Record<string, Record<string, unknown>> = {};
const dnsError = (code: string) => Object.assign(new Error(code), { code });
function lookup(type: string) {
  return async (name: string) => {
    const value = zone[name]?.[type];
    if (value === undefined) throw dnsError("ENODATA");
    return value;
  };
}

// --- TLS: tls.connect() returns a fake socket that the test drives.
type FakeSocket = EventEmitter & Record<string, unknown>;
let tlsBehaviour: (socket: FakeSocket, onSecure: () => void) => void = () => {};
const tlsConnectMock = vi.fn((_options: unknown, onSecure: () => void) => {
  const socket = Object.assign(new EventEmitter(), { end: vi.fn(), destroy: vi.fn() }) as unknown as FakeSocket;
  queueMicrotask(() => tlsBehaviour(socket, onSecure));
  return socket;
});

vi.mock("node:dns", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:dns")>();
  return {
    ...actual,
    promises: {
      ...actual.promises,
      resolve4: lookup("A"),
      resolve6: lookup("AAAA"),
      resolveMx: lookup("MX"),
      resolveNs: lookup("NS"),
      resolveTxt: lookup("TXT"),
      resolveCname: lookup("CNAME"),
      resolveSoa: lookup("SOA"),
      resolveCaa: lookup("CAA"),
    },
  };
});
vi.mock("node:tls", () => ({ default: { connect: tlsConnectMock }, connect: tlsConnectMock }));
vi.mock("@/lib/security/ssrf", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/security/ssrf")>();
  return { ...actual, resolveAndAssertPublic: async (hostname: string) => ({ hostname, addresses: ["203.0.113.80"] }) };
});

const { analyzeDns } = await import("@/services/dns");
const { analyzeTls } = await import("@/services/tls");

beforeEach(() => {
  for (const key of Object.keys(zone)) delete zone[key];
  tlsConnectMock.mockClear();
});

describe("analyzeDns", () => {
  it("collects every record type, sorts MX by priority and joins DMARC chunks", async () => {
    zone["example.com"] = {
      A: ["203.0.113.1"],
      AAAA: ["2001:4860::1"],
      MX: [{ priority: 20, exchange: "mx2.example.com" }, { priority: 10, exchange: "mx1.example.com" }],
      NS: ["ns1.example.net", "ns2.example.net"],
      TXT: [["v=spf1 -all"]],
      SOA: { nsname: "ns1.example.net", hostmaster: "hostmaster.example.com", serial: 1, refresh: 2, retry: 3, expire: 4, minttl: 5 },
      CAA: [{ critical: 0, issue: "letsencrypt.org" }],
    };
    zone["_dmarc.example.com"] = { TXT: [["v=DMARC1; ", "p=reject"]] };

    const result = await analyzeDns("example.com");
    expect(result.status).toBe("ok");
    expect(result.data).toMatchObject({
      a: ["203.0.113.1"],
      aaaa: ["2001:4860::1"],
      mx: [{ priority: 10 }, { priority: 20 }],
      ns: ["ns1.example.net", "ns2.example.net"],
      soa: { serial: 1, minttl: 5 },
      caa: [{ critical: 0, issue: "letsencrypt.org" }],
      dmarcRecord: "v=DMARC1; p=reject",
    });
    expect(result.data!.caaInheritedFrom).toBeUndefined();
  });

  it("reports an error when the name has no records at all", async () => {
    expect(await analyzeDns("missing.example")).toMatchObject({ status: "error", message: expect.stringMatching(/No DNS records/) });
  });

  it("doesn't count CAA inherited from a parent as evidence that the name exists", async () => {
    zone["example.com"] = { CAA: [{ critical: 0, issue: "letsencrypt.org" }] };
    expect((await analyzeDns("ghost.example.com")).status).toBe("error");

    zone["www.example.com"] = { A: ["203.0.113.2"] };
    const result = await analyzeDns("www.example.com");
    expect(result.data).toMatchObject({ caa: [{ issue: "letsencrypt.org" }], caaInheritedFrom: "example.com" });
  });
});

describe("analyzeTls", () => {
  const validTo = new Date(Date.now() + 45 * 86_400_000);
  const cert = {
    issuer: { O: "Let's Encrypt", CN: "R11" },
    subject: { CN: "example.com" },
    valid_from: new Date(Date.now() - 45 * 86_400_000).toUTCString(),
    valid_to: validTo.toUTCString(),
    subjectaltname: "DNS:example.com, DNS:www.example.com",
  };

  function handshake(overrides: Record<string, unknown> = {}, peer: unknown = cert) {
    tlsBehaviour = (socket, onSecure) => {
      Object.assign(socket, { authorized: true, authorizationError: null, getProtocol: () => "TLSv1.3", getPeerCertificate: () => peer, ...overrides });
      onSecure();
    };
  }

  it("connects to the pinned IP with SNI for the hostname and reports the certificate", async () => {
    handshake();
    const result = await analyzeTls("example.com");

    expect(tlsConnectMock).toHaveBeenCalledWith(
      expect.objectContaining({ host: "203.0.113.80", port: 443, servername: "example.com", rejectUnauthorized: false }),
      expect.any(Function)
    );
    expect(result).toMatchObject({
      status: "ok",
      data: {
        secure: true,
        tlsVersion: "TLSv1.3",
        issuer: "Let's Encrypt",
        subject: "example.com",
        subjectAltNames: ["example.com", "www.example.com"],
        selfSigned: false,
        authorized: true,
        authorizationError: null,
      },
    });
    expect(result.data!.daysRemaining).toBe(45);
  });

  it("flags self-signed and untrusted certificates", async () => {
    handshake({ authorized: false, authorizationError: "DEPTH_ZERO_SELF_SIGNED_CERT" }, { ...cert, issuer: { CN: "example.com" }, subject: { CN: "example.com" } });
    expect((await analyzeTls("example.com")).data).toMatchObject({ selfSigned: true, authorized: false, authorizationError: "DEPTH_ZERO_SELF_SIGNED_CERT", issuer: "example.com" });
  });

  it("omits SNI for IP literals", async () => {
    handshake();
    await analyzeTls("203.0.113.80");
    expect(tlsConnectMock.mock.calls[0]![0]).toMatchObject({ servername: undefined });
  });

  it("reports a server that presents no certificate", async () => {
    handshake({}, {});
    expect(await analyzeTls("example.com")).toEqual({ status: "error", message: "Server did not present a certificate." });
  });

  it("treats a refused connection as 'no HTTPS', other failures as errors, and times out", async () => {
    tlsBehaviour = (socket) => socket.emit("error", dnsError("ECONNREFUSED"));
    expect((await analyzeTls("example.com")).status).toBe("not_applicable");

    tlsBehaviour = (socket) => socket.emit("error", Object.assign(new Error("wrong version number"), { code: "ERR_SSL_WRONG_VERSION_NUMBER" }));
    expect(await analyzeTls("example.com")).toMatchObject({ status: "error", message: expect.stringMatching(/wrong version number/) });

    tlsBehaviour = (socket) => socket.emit("timeout");
    expect(await analyzeTls("example.com")).toEqual({ status: "error", message: "TLS connection timed out." });
  });
});

describe("technology detection", () => {
  afterEach(() => vi.restoreAllMocks());

  it("matches header and body signals with their evidence", async () => {
    const { detectTechnologies } = await import("@/services/technology");
    const found = detectTechnologies({
      statusCode: 200,
      finalUrl: "https://example.com/",
      redirectChain: [],
      headers: { server: "cloudflare", "cf-ray": "abc", "x-powered-by": "Express", "x-vercel-id": "fra1::x" },
      body: '<link href="/wp-content/themes/x.css"><script src="https://www.googletagmanager.com/gtm.js?id=GTM-1"></script><app-root ng-version="17.0.0"></app-root>',
    });
    const names = found.map((t) => t.name);
    expect(names).toEqual(expect.arrayContaining(["Cloudflare", "Express", "Vercel", "WordPress", "Google Tag Manager", "Angular"]));
    expect(found.find((t) => t.name === "Cloudflare")).toMatchObject({ category: "CDN", evidence: "Header: cf-ray" });
    expect(names).not.toContain("nginx");
  });
});

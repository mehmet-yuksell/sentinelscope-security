import http from "node:http";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

// The SSRF guard (correctly) refuses to connect to 127.0.0.1, so for these
// tests every hostname is "resolved" to the local test server instead. The
// SSRF rules themselves are covered in tests/unit/ssrf.test.ts.
vi.mock("@/lib/security/ssrf", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/security/ssrf")>();
  return {
    ...actual,
    resolveAndAssertPublic: async (hostname: string) => ({ hostname, addresses: ["127.0.0.1"] }),
    assertSafePort: () => {},
  };
});

const { safeRequest } = await import("@/lib/net/safeRequest");
const { detectTechnologies } = await import("@/services/technology");

const HTML = '<html><head><script id="__NEXT_DATA__" type="application/json">{}</script></head><body>ok</body></html>';

let server: http.Server;
let baseUrl = "";

beforeAll(async () => {
  server = http.createServer((req, res) => {
    switch (req.url) {
      case "/page":
        res.writeHead(200, { "content-type": "text/html", server: "nginx" });
        res.end(HTML);
        return;
      case "/large":
        res.writeHead(200, { "content-type": "text/plain" });
        res.end("a".repeat(10_000));
        return;
      case "/redirect":
        res.writeHead(301, { location: "/page" });
        res.end();
        return;
      default:
        res.writeHead(404);
        res.end();
    }
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const { port } = server.address() as { port: number };
  baseUrl = `http://target.test:${port}`;
});

afterAll(() => {
  server.closeAllConnections();
  server.close();
});

describe("safeRequest", () => {
  it("returns the response body, not just the headers", async () => {
    const res = await safeRequest(`${baseUrl}/page`);
    expect(res.statusCode).toBe(200);
    expect(res.body).toBe(HTML);
  });

  it("feeds the body into body-marker technology detection", async () => {
    const res = await safeRequest(`${baseUrl}/page`);
    const names = detectTechnologies(res).map((t) => t.name);
    expect(names).toContain("Next.js");
    expect(names).toContain("nginx");
  });

  it("truncates the body at maxBodyBytes instead of failing", async () => {
    const res = await safeRequest(`${baseUrl}/large`, { maxBodyBytes: 1024 });
    expect(res.body.length).toBe(1024);
  });

  it("follows redirects and records the chain", async () => {
    const res = await safeRequest(`${baseUrl}/redirect`);
    expect(res.finalUrl).toBe(`${baseUrl}/page`);
    expect(res.redirectChain).toEqual([`${baseUrl}/redirect`]);
    expect(res.body).toBe(HTML);
  });
});

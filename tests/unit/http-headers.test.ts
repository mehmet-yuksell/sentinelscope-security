import { describe, expect, it } from "vitest";
import { HEADER_CHECKS, buildHttpInfo } from "@/services/http";
import type { SafeResponse } from "@/lib/net/safeRequest";

function check(header: string) {
  const def = HEADER_CHECKS.find((c) => c.header === header);
  if (!def) throw new Error(`No header check registered for ${header}`);
  return def;
}

describe("HTTP security header evaluation", () => {
  it("passes a strong Strict-Transport-Security header and warns on a short max-age", () => {
    expect(check("strict-transport-security").evaluate("max-age=31536000; includeSubDomains").status).toBe("pass");
    expect(check("strict-transport-security").evaluate("max-age=60").status).toBe("warning");
    expect(check("strict-transport-security").evaluate(undefined).status).toBe("missing");
  });

  it("flags a CSP with unsafe-inline/unsafe-eval as a warning, not a pass", () => {
    expect(check("content-security-policy").evaluate("default-src 'self'").status).toBe("pass");
    expect(check("content-security-policy").evaluate("script-src 'unsafe-inline'").status).toBe("warning");
    expect(check("content-security-policy").evaluate(undefined).status).toBe("missing");
  });

  it("requires the exact value 'nosniff' for X-Content-Type-Options", () => {
    expect(check("x-content-type-options").evaluate("nosniff").status).toBe("pass");
    expect(check("x-content-type-options").evaluate("something-else").status).toBe("warning");
    expect(check("x-content-type-options").evaluate(undefined).status).toBe("missing");
  });

  it("accepts DENY/SAMEORIGIN for X-Frame-Options but warns on other values", () => {
    expect(check("x-frame-options").evaluate("DENY").status).toBe("pass");
    expect(check("x-frame-options").evaluate("SAMEORIGIN").status).toBe("pass");
    expect(check("x-frame-options").evaluate("ALLOW-FROM https://example.com").status).toBe("warning");
  });

  it("warns on an overly permissive Referrer-Policy", () => {
    expect(check("referrer-policy").evaluate("unsafe-url").status).toBe("warning");
    expect(check("referrer-policy").evaluate("no-referrer").status).toBe("pass");
  });

  it("treats any Permissions-Policy value as a pass", () => {
    expect(check("permissions-policy").evaluate("geolocation=()").status).toBe("pass");
    expect(check("permissions-policy").evaluate(undefined).status).toBe("missing");
  });
});

describe("buildHttpInfo", () => {
  it("extracts server, x-powered-by, and redirect metadata from a raw response", () => {
    const response: SafeResponse = {
      statusCode: 200,
      headers: { server: "nginx/1.25.0", "x-powered-by": "Express" },
      body: "<html></html>",
      finalUrl: "https://example.com/",
      redirectChain: ["http://example.com/"],
    };

    const info = buildHttpInfo(response);
    expect(info.server).toBe("nginx/1.25.0");
    expect(info.poweredBy).toBe("Express");
    expect(info.redirected).toBe(true);
    expect(info.securityHeaders).toHaveLength(HEADER_CHECKS.length);
  });
});

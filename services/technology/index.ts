import type { SafeResponse } from "@/lib/net/safeRequest";
import type { TechnologyEntry } from "@/types/analysis";

interface Signal {
  category: string;
  name: string;
  confidence: TechnologyEntry["confidence"];
  test: (ctx: { headers: Record<string, string>; body: string }) => string | null;
}

const SIGNALS: Signal[] = [
  {
    category: "Web Server",
    name: "nginx",
    confidence: "high",
    test: ({ headers }) => (/nginx/i.test(headers["server"] ?? "") ? `Server: ${headers["server"]}` : null),
  },
  {
    category: "Web Server",
    name: "Apache",
    confidence: "high",
    test: ({ headers }) => (/apache/i.test(headers["server"] ?? "") ? `Server: ${headers["server"]}` : null),
  },
  {
    category: "Web Server",
    name: "Microsoft IIS",
    confidence: "high",
    test: ({ headers }) => (/iis/i.test(headers["server"] ?? "") ? `Server: ${headers["server"]}` : null),
  },
  {
    category: "Web Server",
    name: "LiteSpeed",
    confidence: "high",
    test: ({ headers }) => (/litespeed/i.test(headers["server"] ?? "") ? `Server: ${headers["server"]}` : null),
  },
  {
    category: "CDN",
    name: "Cloudflare",
    confidence: "high",
    test: ({ headers }) =>
      headers["cf-ray"] || /cloudflare/i.test(headers["server"] ?? "")
        ? `Header: ${headers["cf-ray"] ? "cf-ray" : "server"}`
        : null,
  },
  {
    category: "CDN",
    name: "Amazon CloudFront",
    confidence: "high",
    test: ({ headers }) => (headers["x-amz-cf-id"] ? "Header: x-amz-cf-id" : null),
  },
  {
    category: "CDN",
    name: "Fastly",
    confidence: "high",
    test: ({ headers }) => (headers["x-fastly-request-id"] || headers["x-served-by"]?.includes("cache-") ? "Header: x-served-by / x-fastly-request-id" : null),
  },
  {
    category: "Hosting Platform",
    name: "Vercel",
    confidence: "high",
    test: ({ headers }) => (headers["x-vercel-id"] ? "Header: x-vercel-id" : null),
  },
  {
    category: "Framework",
    name: "Next.js",
    confidence: "medium",
    test: ({ headers, body }) =>
      headers["x-powered-by"]?.toLowerCase().includes("next.js")
        ? "Header: x-powered-by"
        : body.includes("__NEXT_DATA__")
        ? "Body: __NEXT_DATA__ marker"
        : null,
  },
  {
    category: "Framework",
    name: "Express",
    confidence: "medium",
    test: ({ headers }) => (headers["x-powered-by"]?.toLowerCase().includes("express") ? "Header: x-powered-by" : null),
  },
  {
    category: "Framework",
    name: "ASP.NET",
    confidence: "medium",
    test: ({ headers }) =>
      headers["x-powered-by"]?.toLowerCase().includes("asp.net") || headers["x-aspnet-version"]
        ? "Header: x-powered-by / x-aspnet-version"
        : null,
  },
  {
    category: "Framework",
    name: "Angular",
    confidence: "medium",
    test: ({ body }) => (/ng-version="([^"]+)"/i.test(body) ? "Body: ng-version attribute" : null),
  },
  {
    category: "CMS",
    name: "WordPress",
    confidence: "medium",
    test: ({ body }) =>
      /wp-content|wp-includes/i.test(body) || /generator" content="WordPress/i.test(body)
        ? "Body: wp-content/wp-includes path or generator meta tag"
        : null,
  },
  {
    category: "CMS",
    name: "Shopify",
    confidence: "high",
    test: ({ headers, body }) =>
      headers["x-shopify-stage"] || /cdn\.shopify\.com/i.test(body) ? "Header/body: Shopify CDN reference" : null,
  },
  {
    category: "Analytics",
    name: "Google Analytics",
    confidence: "medium",
    test: ({ body }) =>
      /www\.google-analytics\.com|googletagmanager\.com\/gtag/i.test(body) ? "Body: Google Analytics script reference" : null,
  },
  {
    category: "Analytics",
    name: "Google Tag Manager",
    confidence: "medium",
    test: ({ body }) => (/googletagmanager\.com\/gtm\.js/i.test(body) ? "Body: GTM script reference" : null),
  },
];

/**
 * Passive technology fingerprinting from response headers and HTML body
 * markers only — no active probing of endpoints or version enumeration.
 */
export function detectTechnologies(response: SafeResponse): TechnologyEntry[] {
  const ctx = { headers: response.headers, body: response.body.slice(0, 200_000) };
  const found: TechnologyEntry[] = [];

  for (const signal of SIGNALS) {
    const evidence = signal.test(ctx);
    if (evidence) {
      found.push({ category: signal.category, name: signal.name, confidence: signal.confidence, evidence });
    }
  }

  return found;
}

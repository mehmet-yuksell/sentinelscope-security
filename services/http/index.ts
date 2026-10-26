import { safeRequest, type SafeResponse } from "@/lib/net/safeRequest";
import type { HttpHeaderCheck, HttpInfo } from "@/types/analysis";

interface HeaderCheckDefinition {
  header: string;
  description: string;
  evaluate: (value: string | undefined) => { status: HttpHeaderCheck["status"] };
}

export const HEADER_CHECKS: HeaderCheckDefinition[] = [
  {
    header: "strict-transport-security",
    description: "Forces browsers to use HTTPS for this domain, preventing protocol-downgrade attacks.",
    evaluate: (value) => {
      if (!value) return { status: "missing" };
      const match = /max-age=(\d+)/i.exec(value);
      const maxAge = match ? Number(match[1]) : 0;
      return { status: maxAge >= 15552000 ? "pass" : "warning" }; // ~180 days
    },
  },
  {
    header: "content-security-policy",
    description: "Restricts which sources of script, style, and other content the page may load, mitigating XSS.",
    evaluate: (value) => {
      if (!value) return { status: "missing" };
      const weak = /unsafe-inline|unsafe-eval|\*(?!\.)/i.test(value);
      return { status: weak ? "warning" : "pass" };
    },
  },
  {
    header: "x-content-type-options",
    description: "Prevents browsers from MIME-sniffing a response away from its declared content type.",
    evaluate: (value) => ({ status: value?.toLowerCase() === "nosniff" ? "pass" : value ? "warning" : "missing" }),
  },
  {
    header: "x-frame-options",
    description: "Controls whether the page can be embedded in a frame, mitigating clickjacking.",
    evaluate: (value) => {
      if (!value) return { status: "missing" };
      return { status: ["deny", "sameorigin"].includes(value.toLowerCase()) ? "pass" : "warning" };
    },
  },
  {
    header: "referrer-policy",
    description: "Controls how much referrer information is leaked to other origins on navigation.",
    evaluate: (value) => {
      if (!value) return { status: "missing" };
      return { status: value.toLowerCase() === "unsafe-url" ? "warning" : "pass" };
    },
  },
  {
    header: "permissions-policy",
    description: "Restricts which browser features and APIs (camera, geolocation, etc.) the page may use.",
    evaluate: (value) => ({ status: value ? "pass" : "missing" }),
  },
];

function buildSecurityHeaders(headers: Record<string, string>): HttpHeaderCheck[] {
  return HEADER_CHECKS.map(({ header, description, evaluate }) => {
    const value = headers[header];
    const { status } = evaluate(value);
    return { header, status, value: value ?? null, description };
  });
}

/**
 * Performs the single outbound fetch used for both HTTP header analysis and
 * technology detection, trying HTTPS first (or HTTP first for explicit
 * http:// targets) so we only ever hit the network once per analysis.
 */
export async function fetchTargetPage(hostname: string, preferHttps: boolean): Promise<SafeResponse> {
  const attempts = preferHttps
    ? [`https://${hostname}/`, `http://${hostname}/`]
    : [`http://${hostname}/`, `https://${hostname}/`];

  let lastError: string | undefined;
  for (const url of attempts) {
    try {
      return await safeRequest(url, { method: "GET" });
    } catch (err) {
      lastError = (err as Error).message;
    }
  }
  throw new Error(lastError ?? "HTTP request failed for an unknown reason.");
}

export function buildHttpInfo(response: SafeResponse): HttpInfo {
  return {
    finalUrl: response.finalUrl,
    statusCode: response.statusCode,
    redirected: response.redirectChain.length > 0,
    redirectChain: response.redirectChain,
    headers: response.headers,
    securityHeaders: buildSecurityHeaders(response.headers),
    server: response.headers["server"] ?? null,
    poweredBy: response.headers["x-powered-by"] ?? null,
  };
}

import http from "node:http";
import https from "node:https";
import { isIP } from "node:net";
import { URL } from "node:url";
import { resolveAndAssertPublic, assertSafePort, SsrfBlockedError } from "@/lib/security/ssrf";

export interface SafeRequestOptions {
  method?: string;
  headers?: Record<string, string>;
  timeoutMs?: number;
  maxRedirects?: number;
  maxBodyBytes?: number;
}

export interface SafeResponse {
  statusCode: number;
  headers: Record<string, string>;
  body: string;
  finalUrl: string;
  redirectChain: string[];
}

const DEFAULT_TIMEOUT_MS = 8000;
const DEFAULT_MAX_REDIRECTS = 5;
const DEFAULT_MAX_BODY_BYTES = 2 * 1024 * 1024; // 2MB
const USER_AGENT = "SentinelScope/1.0 (+passive-security-scanner; non-destructive)";

function normalizeHeaders(raw: http.IncomingHttpHeaders): Record<string, string> {
  const headers: Record<string, string> = {};
  for (const [key, value] of Object.entries(raw)) {
    if (typeof value === "string") headers[key] = value;
    else if (Array.isArray(value)) headers[key] = value.join(", ");
  }
  return headers;
}

interface HopResult {
  statusCode: number;
  headers: Record<string, string>;
  body: string;
  redirectTo?: string;
}

/**
 * Performs a single HTTP(S) hop against a pre-validated, pinned IP address
 * so the TCP/TLS connection cannot be redirected by a DNS change between
 * the SSRF check and the actual connect (DNS-rebinding protection).
 */
function performHop(
  url: URL,
  pinnedIp: string,
  options: Required<Pick<SafeRequestOptions, "method" | "timeoutMs" | "maxBodyBytes">> &
    Pick<SafeRequestOptions, "headers">
): Promise<HopResult> {
  return new Promise((resolve, reject) => {
    let settled = false;
    const lib = url.protocol === "https:" ? https : http;
    const port = url.port ? Number(url.port) : url.protocol === "https:" ? 443 : 80;

    const req = lib.request(
      {
        host: pinnedIp,
        port,
        path: `${url.pathname}${url.search}`,
        method: options.method,
        headers: {
          Host: url.hostname,
          "User-Agent": USER_AGENT,
          Accept: "text/html,application/xhtml+xml,*/*;q=0.8",
          ...options.headers,
        },
        // SNI + certificate hostname verification target the original hostname,
        // not the pinned IP we connect to. SNI must not be an IP literal.
        servername: url.protocol === "https:" && isIP(url.hostname) === 0 ? url.hostname : undefined,
        timeout: options.timeoutMs,
        // Header/technology analysis intentionally still runs against sites with
        // invalid certificates; TLS validity is scored separately by the TLS service.
        rejectUnauthorized: false,
      },
      (res) => {
        let size = 0;
        const chunks: Buffer[] = [];
        res.on("data", (chunk: Buffer) => {
          if (settled) return;
          size += chunk.length;
          chunks.push(chunk);
          if (size > options.maxBodyBytes) {
            // Keep the first maxBodyBytes for analysis and stop reading the rest.
            settled = true;
            req.destroy();
            resolve({
              statusCode: res.statusCode ?? 0,
              headers: normalizeHeaders(res.headers),
              body: Buffer.concat(chunks).subarray(0, options.maxBodyBytes).toString("utf-8"),
            });
          }
        });
        res.on("end", () => {
          if (settled) return;
          settled = true;
          const headers = normalizeHeaders(res.headers);
          const statusCode = res.statusCode ?? 0;
          if ([301, 302, 303, 307, 308].includes(statusCode) && headers.location) {
            resolve({ statusCode, headers, body: "", redirectTo: headers.location });
            return;
          }
          resolve({ statusCode, headers, body: Buffer.concat(chunks).toString("utf-8") });
        });
      }
    );

    req.on("timeout", () => {
      if (settled) return;
      settled = true;
      req.destroy(new Error("Request timed out"));
    });
    req.on("error", (err) => {
      if (settled) return;
      settled = true;
      reject(err);
    });
    req.end();
  });
}

/**
 * SSRF-safe HTTP(S) fetch for user-supplied targets. Validates the hostname
 * and every redirect hop against reserved/private address space, pins each
 * connection to the validated IP, and enforces timeout + response-size caps.
 */
export async function safeRequest(targetUrl: string, options: SafeRequestOptions = {}): Promise<SafeResponse> {
  const maxRedirects = options.maxRedirects ?? DEFAULT_MAX_REDIRECTS;
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxBodyBytes = options.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES;

  let currentUrl = new URL(targetUrl);
  const redirectChain: string[] = [];

  for (let hop = 0; hop <= maxRedirects; hop++) {
    if (currentUrl.protocol !== "http:" && currentUrl.protocol !== "https:") {
      throw new SsrfBlockedError(currentUrl.hostname, `unsupported protocol "${currentUrl.protocol}"`);
    }
    if (currentUrl.username || currentUrl.password) {
      throw new SsrfBlockedError(currentUrl.hostname, "credentials in URL are not permitted");
    }
    const port = currentUrl.port ? Number(currentUrl.port) : currentUrl.protocol === "https:" ? 443 : 80;
    assertSafePort(port);

    const resolved = await resolveAndAssertPublic(currentUrl.hostname);
    const pinnedIp = resolved.addresses[0]!;

    const hopResult = await performHop(currentUrl, pinnedIp, {
      method: options.method ?? "GET",
      headers: options.headers,
      timeoutMs,
      maxBodyBytes,
    });

    if (hopResult.redirectTo) {
      redirectChain.push(currentUrl.toString());
      currentUrl = new URL(hopResult.redirectTo, currentUrl);
      continue;
    }

    return {
      statusCode: hopResult.statusCode,
      headers: hopResult.headers,
      body: hopResult.body,
      finalUrl: currentUrl.toString(),
      redirectChain,
    };
  }

  throw new Error(`Too many redirects (> ${maxRedirects})`);
}

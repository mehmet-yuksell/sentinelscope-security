import tls from "node:tls";
import { isIP } from "node:net";
import { resolveAndAssertPublic } from "@/lib/security/ssrf";
import type { TlsInfo, ProviderResult } from "@/types/analysis";

const CONNECT_TIMEOUT_MS = 8000;

/**
 * Opens a real TLS handshake against the target (pinned to its
 * SSRF-validated IP) and reports certificate/protocol details. A refused or
 * unreachable connection is reported as "not_applicable" (the site simply
 * doesn't serve HTTPS on this port) rather than as a system error.
 */
export async function analyzeTls(hostname: string, port = 443): Promise<ProviderResult<TlsInfo>> {
  let pinnedIp: string;
  try {
    const resolved = await resolveAndAssertPublic(hostname);
    pinnedIp = resolved.addresses[0]!;
  } catch (err) {
    return { status: "error", message: (err as Error).message };
  }

  return new Promise((resolve) => {
    let settled = false;

    const socket = tls.connect(
      {
        host: pinnedIp,
        port,
        servername: isIP(hostname) === 0 ? hostname : undefined,
        timeout: CONNECT_TIMEOUT_MS,
        // We want to see and report invalid/expired/self-signed certs, not
        // reject the connection before we can inspect them.
        rejectUnauthorized: false,
      },
      () => {
        if (settled) return;
        settled = true;

        const cert = socket.getPeerCertificate(true);
        if (!cert || Object.keys(cert).length === 0) {
          resolve({ status: "error", message: "Server did not present a certificate." });
          socket.end();
          return;
        }

        const validFrom = cert.valid_from ? new Date(cert.valid_from) : null;
        const validTo = cert.valid_to ? new Date(cert.valid_to) : null;
        const daysRemaining = validTo
          ? Math.round((validTo.getTime() - Date.now()) / (1000 * 60 * 60 * 24))
          : null;

        const sanRaw = cert.subjectaltname ?? "";
        const subjectAltNames = sanRaw
          .split(",")
          .map((entry) => entry.trim().replace(/^DNS:/, ""))
          .filter(Boolean);

        const selfSigned =
          !!cert.issuer && !!cert.subject && JSON.stringify(cert.issuer) === JSON.stringify(cert.subject);

        const data: TlsInfo = {
          secure: true,
          tlsVersion: socket.getProtocol(),
          issuer: cert.issuer?.O ?? cert.issuer?.CN ?? null,
          subject: cert.subject?.CN ?? null,
          validFrom: validFrom ? validFrom.toISOString() : null,
          validTo: validTo ? validTo.toISOString() : null,
          daysRemaining,
          subjectAltNames,
          selfSigned,
          authorized: socket.authorized,
          authorizationError: socket.authorizationError ? String(socket.authorizationError) : null,
        };

        resolve({ status: "ok", data });
        socket.end();
      }
    );

    socket.on("error", (err: NodeJS.ErrnoException) => {
      if (settled) return;
      settled = true;
      if (["ECONNREFUSED", "ENETUNREACH", "EHOSTUNREACH", "ECONNRESET"].includes(err.code ?? "")) {
        resolve({ status: "not_applicable", message: "Target does not accept HTTPS connections on this port." });
      } else {
        resolve({ status: "error", message: `TLS handshake failed: ${err.message}` });
      }
      socket.destroy();
    });

    socket.on("timeout", () => {
      if (settled) return;
      settled = true;
      resolve({ status: "error", message: "TLS connection timed out." });
      socket.destroy();
    });
  });
}

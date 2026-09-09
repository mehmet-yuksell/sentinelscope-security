import type { ProviderResult, TlsInfo } from "@/types/analysis";
import { ProviderStatusNotice } from "./ProviderStatusNotice";
import { formatDate } from "@/utils/riskDisplay";

function Stat({ label, value, tone }: { label: string; value: string; tone?: string }) {
  return (
    <div className="rounded-lg border border-base-700 bg-base-900/40 p-4">
      <p className="text-xs uppercase tracking-widest text-base-500">{label}</p>
      <p className={`mt-1 text-lg font-semibold ${tone ?? "text-base-100"}`}>{value}</p>
    </div>
  );
}

export function TlsPanel({ tls }: { tls: ProviderResult<TlsInfo> }) {
  if (tls.status !== "ok" || !tls.data) {
    return <ProviderStatusNotice status={tls.status} message={tls.message} />;
  }

  const t = tls.data;
  const expiryTone =
    t.daysRemaining === null ? undefined : t.daysRemaining < 0 ? "text-risk-critical" : t.daysRemaining < 30 ? "text-risk-moderate" : "text-accent-500";

  return (
    <div className="space-y-6">
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Stat label="TLS Status" value={t.authorized ? "Secure" : "Untrusted"} tone={t.authorized ? "text-accent-500" : "text-risk-high"} />
        <Stat label="TLS Version" value={t.tlsVersion ?? "Unknown"} />
        <Stat label="Issuer" value={t.issuer ?? "Unknown"} />
        <Stat label="Expires" value={t.daysRemaining === null ? "Unknown" : `${t.daysRemaining} days`} tone={expiryTone} />
      </div>

      <div className="space-y-1 rounded-lg border border-base-700 bg-base-900/40 p-4 text-sm text-base-300">
        <p>
          <span className="text-base-500">Subject:</span> {t.subject ?? "Unknown"}
        </p>
        <p>
          <span className="text-base-500">Valid From:</span> {formatDate(t.validFrom)}
        </p>
        <p>
          <span className="text-base-500">Valid To:</span> {formatDate(t.validTo)}
        </p>
        {t.selfSigned && <p className="mt-2 text-risk-high">⚠ Self-signed certificate</p>}
        {t.authorizationError && <p className="mt-1 text-risk-high">⚠ {t.authorizationError}</p>}
      </div>

      {t.subjectAltNames.length > 0 && (
        <div>
          <h4 className="mb-2 text-xs font-semibold uppercase tracking-widest text-base-500">Subject Alternative Names</h4>
          <div className="flex flex-wrap gap-2">
            {t.subjectAltNames.map((san) => (
              <span key={san} className="rounded bg-base-800 px-2.5 py-1 font-mono text-xs text-base-300">
                {san}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

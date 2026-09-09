import type { DomainIntelInfo, ProviderResult } from "@/types/analysis";
import { ProviderStatusNotice } from "./ProviderStatusNotice";
import { formatDate } from "@/utils/riskDisplay";

export function DomainPanel({ domain }: { domain: ProviderResult<DomainIntelInfo> }) {
  if (domain.status !== "ok" || !domain.data) {
    return <ProviderStatusNotice status={domain.status} message={domain.message} />;
  }

  const d = domain.data;

  return (
    <div className="space-y-6">
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <div className="card-elevated rounded-xl border border-base-700 bg-base-900/50 p-4">
          <p className="text-xs font-semibold uppercase tracking-widest text-base-500">Registrar</p>
          <p className="mt-1.5 text-sm font-medium text-base-100">{d.registrar ?? "Unknown"}</p>
        </div>
        <div className="card-elevated rounded-xl border border-base-700 bg-base-900/50 p-4">
          <p className="text-xs font-semibold uppercase tracking-widest text-base-500">Registered</p>
          <p className="mt-1.5 text-sm font-medium text-base-100">{formatDate(d.createdDate)}</p>
        </div>
        <div className="card-elevated rounded-xl border border-base-700 bg-base-900/50 p-4">
          <p className="text-xs font-semibold uppercase tracking-widest text-base-500">Expires</p>
          <p className="mt-1.5 text-sm font-medium text-base-100">{formatDate(d.expiresDate)}</p>
        </div>
        <div className="card-elevated rounded-xl border border-base-700 bg-base-900/50 p-4">
          <p className="text-xs font-semibold uppercase tracking-widest text-base-500">Domain Age</p>
          <p className="mt-1.5 text-sm font-medium text-base-100">{d.domainAgeDays !== null ? `${d.domainAgeDays} days` : "Unknown"}</p>
        </div>
      </div>

      {d.nameservers.length > 0 && (
        <div>
          <h4 className="mb-2 text-xs font-semibold uppercase tracking-widest text-base-500">Nameservers</h4>
          <div className="flex flex-wrap gap-2">
            {d.nameservers.map((ns) => (
              <span key={ns} className="rounded bg-base-800 px-2.5 py-1 font-mono text-xs text-base-300">
                {ns}
              </span>
            ))}
          </div>
        </div>
      )}

      {d.status.length > 0 && (
        <div>
          <h4 className="mb-2 text-xs font-semibold uppercase tracking-widest text-base-500">Status</h4>
          <div className="flex flex-wrap gap-2">
            {d.status.map((s) => (
              <span key={s} className="rounded bg-base-800 px-2.5 py-1 text-xs text-base-300">
                {s}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

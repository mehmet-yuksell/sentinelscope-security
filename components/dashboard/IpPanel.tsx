import type { IpIntelInfo, ProviderResult } from "@/types/analysis";
import { ProviderStatusNotice } from "./ProviderStatusNotice";

export function IpPanel({ ip }: { ip: ProviderResult<IpIntelInfo> }) {
  if (ip.status !== "ok" || !ip.data) {
    return <ProviderStatusNotice status={ip.status} message={ip.message} />;
  }

  const d = ip.data;
  const rows: [string, string][] = [
    ["IP Address", d.ip],
    ["ASN", d.asn ?? "Unknown"],
    ["Organization", d.organization ?? "Unknown"],
    ["Country", d.country ? `${d.country}${d.countryCode ? ` (${d.countryCode})` : ""}` : "Unknown"],
    ["City", d.city ?? "Unknown"],
    ["Reverse DNS", d.reverseDns ?? "None"],
  ];

  return (
    <div className="grid gap-4 sm:grid-cols-2">
      {rows.map(([label, value]) => (
        <div key={label} className="card-elevated rounded-xl border border-base-700 bg-base-900/50 p-4">
          <p className="text-xs font-semibold uppercase tracking-widest text-base-500">{label}</p>
          <p className="mt-1.5 break-all font-mono text-sm font-medium text-base-100">{value}</p>
        </div>
      ))}
      {d.isDatacenter !== null && (
        <div className="card-elevated rounded-xl border border-base-700 bg-base-900/50 p-4 sm:col-span-2">
          <p className="text-xs font-semibold uppercase tracking-widest text-base-500">Hosting Type (heuristic)</p>
          <p className="mt-1 text-sm text-base-100">
            {d.isDatacenter ? "Likely datacenter / cloud hosting" : "Likely non-datacenter network"}
          </p>
        </div>
      )}
    </div>
  );
}

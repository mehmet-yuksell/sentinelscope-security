import type { DnsRecordSet, ProviderResult } from "@/types/analysis";
import { ProviderStatusNotice } from "./ProviderStatusNotice";

function RecordGroup({ title, values }: { title: string; values: string[] }) {
  if (values.length === 0) return null;
  return (
    <div className="card-elevated rounded-xl border border-base-700 bg-base-900/50 p-4">
      <h4 className="mb-2 text-xs font-bold uppercase tracking-widest text-accent-400">{title}</h4>
      <ul className="space-y-1.5">
        {values.map((value) => (
          <li key={value} className="break-all rounded-lg bg-base-950/60 px-3 py-2 font-mono text-sm text-base-200">
            {value}
          </li>
        ))}
      </ul>
    </div>
  );
}

export function DnsPanel({ dns }: { dns: ProviderResult<DnsRecordSet> }) {
  if (dns.status !== "ok" || !dns.data) {
    return <ProviderStatusNotice status={dns.status} message={dns.message} />;
  }

  const d = dns.data;

  return (
    <div className="grid gap-6 sm:grid-cols-2">
      <RecordGroup title="A" values={d.a} />
      <RecordGroup title="AAAA" values={d.aaaa} />
      <RecordGroup title="CNAME" values={d.cname} />
      <RecordGroup title="NS" values={d.ns} />
      <RecordGroup title="MX" values={d.mx.map((m) => `${m.priority} ${m.exchange}`)} />
      <RecordGroup title="TXT" values={d.txt.map((chunks) => chunks.join(""))} />
      <RecordGroup title="CAA" values={d.caa.map((c) => `flags=${c.critical} ${c.issue ?? c.issuewild ?? c.iodef ?? ""}`)} />

      {d.soa && (
        <div className="card-elevated rounded-xl border border-base-700 bg-base-900/50 p-4">
          <h4 className="mb-2 text-xs font-bold uppercase tracking-widest text-accent-400">SOA</h4>
          <div className="space-y-1 rounded-lg bg-base-950/60 px-3 py-2.5 font-mono text-xs text-base-300">
            <p>Primary NS: {d.soa.nsname}</p>
            <p>Serial: {d.soa.serial}</p>
            <p>
              Refresh: {d.soa.refresh}s · Retry: {d.soa.retry}s · Expire: {d.soa.expire}s
            </p>
          </div>
        </div>
      )}

      <div className="card-elevated rounded-xl border border-base-700 bg-base-900/50 p-4">
        <h4 className="mb-2 text-xs font-bold uppercase tracking-widest text-accent-400">DMARC</h4>
        <p className="break-all rounded-lg bg-base-950/60 px-3 py-2.5 font-mono text-xs text-base-300">
          {d.dmarcRecord ?? "Not configured"}
        </p>
      </div>
    </div>
  );
}

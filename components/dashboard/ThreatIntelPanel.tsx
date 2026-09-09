import type { ThreatIntelInfo } from "@/types/analysis";
import { ProviderStatusNotice } from "./ProviderStatusNotice";

export function ThreatIntelPanel({ threatIntelligence }: { threatIntelligence: ThreatIntelInfo }) {
  const { virustotal, abuseipdb } = threatIntelligence;

  return (
    <div className="grid gap-6 sm:grid-cols-2">
      <div className="card-elevated rounded-2xl border border-base-700 bg-base-900/60 p-6">
        <h4 className="mb-3 text-sm font-bold text-base-100">VirusTotal</h4>
        {virustotal.status === "ok" && virustotal.data ? (
          <div className="space-y-2 text-sm text-base-300">
            <p>
              <span className="font-semibold text-risk-critical">{virustotal.data.malicious}</span> malicious ·{" "}
              <span className="font-semibold text-risk-moderate">{virustotal.data.suspicious}</span> suspicious ·{" "}
              <span className="font-semibold text-accent-500">{virustotal.data.harmless}</span> harmless
            </p>
            <p className="text-xs text-base-500">{virustotal.data.totalEngines} engine(s) scanned</p>
            {virustotal.data.reportUrl && (
              <a href={virustotal.data.reportUrl} target="_blank" rel="noreferrer" className="inline-block text-xs text-accent-400 underline">
                View full report ↗
              </a>
            )}
          </div>
        ) : (
          <ProviderStatusNotice status={virustotal.status} message={virustotal.message} />
        )}
      </div>

      <div className="card-elevated rounded-2xl border border-base-700 bg-base-900/60 p-6">
        <h4 className="mb-3 text-sm font-bold text-base-100">AbuseIPDB</h4>
        {abuseipdb.status === "ok" && abuseipdb.data ? (
          <div className="space-y-2 text-sm text-base-300">
            <p>
              <span className="font-semibold text-base-100">{abuseipdb.data.abuseConfidenceScore}%</span> abuse confidence
            </p>
            <p className="text-xs text-base-500">{abuseipdb.data.totalReports} report(s) in the last 90 days</p>
            {abuseipdb.data.reportUrl && (
              <a href={abuseipdb.data.reportUrl} target="_blank" rel="noreferrer" className="inline-block text-xs text-accent-400 underline">
                View full report ↗
              </a>
            )}
          </div>
        ) : (
          <ProviderStatusNotice status={abuseipdb.status} message={abuseipdb.message} />
        )}
      </div>
    </div>
  );
}

import { notFound } from "next/navigation";
import type { Metadata } from "next";
import { getAnalysis } from "@/lib/store";
import { ReportPrintButton } from "@/components/dashboard/ReportPrintButton";
import { RISK_LEVEL_LABEL, SEVERITY_LABEL, formatDate, scoreToGrade } from "@/utils/riskDisplay";

interface PageProps {
  params: Promise<{ id: string }>;
}

export async function generateMetadata({ params }: PageProps): Promise<Metadata> {
  const { id } = await params;
  const result = await getAnalysis(id);
  return { title: result ? `${result.target} — Report` : "Report Not Found" };
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="mb-8 break-inside-avoid">
      <h2 className="mb-3 border-b border-neutral-300 pb-1.5 text-sm font-bold uppercase tracking-widest text-neutral-500">{title}</h2>
      {children}
    </section>
  );
}

export default async function ReportPage({ params }: PageProps) {
  const { id } = await params;
  const result = await getAnalysis(id);
  if (!result) notFound();

  return (
    <div className="min-h-screen bg-white text-neutral-900">
      <div className="mx-auto max-w-3xl px-8 py-12">
        <div className="no-print mb-8 flex justify-end">
          <ReportPrintButton />
        </div>

        <header className="mb-10 flex items-start justify-between gap-6 border-b-2 border-neutral-900 pb-6">
          <div>
            <p className="text-xs font-semibold uppercase tracking-widest text-neutral-500">SentinelScope Security Report</p>
            <h1 title={result.target} className="line-clamp-2 mt-1 break-all text-2xl font-bold sm:text-3xl">
              {result.target}
            </h1>
            <p className="mt-2 text-sm text-neutral-600">
              Generated {formatDate(result.timestamp)} · Risk Score {result.riskScore}/100 ({RISK_LEVEL_LABEL[result.riskLevel]})
            </p>
          </div>
          <div className="shrink-0 text-right">
            <p className="text-4xl font-black">{scoreToGrade(result.riskScore)}</p>
            <p className="text-[10px] uppercase tracking-widest text-neutral-500">Grade</p>
          </div>
        </header>

        <Section title="Executive Summary">
          <p className="text-sm leading-relaxed text-neutral-700">{result.risk.summary}</p>
        </Section>

        <Section title="Risk Factors">
          <table className="w-full border-collapse text-sm">
            <thead>
              <tr className="border-b border-neutral-300 text-left text-neutral-500">
                <th className="py-1.5 font-medium">Factor</th>
                <th className="py-1.5 font-medium">Score</th>
                <th className="py-1.5 font-medium">Weight</th>
              </tr>
            </thead>
            <tbody>
              {result.risk.factors.map((f) => (
                <tr key={f.key} className="border-b border-neutral-200">
                  <td className="py-1.5">{f.label}</td>
                  <td className="py-1.5">{f.applicable ? `${f.score}/100` : "N/A"}</td>
                  <td className="py-1.5">{Math.round(f.weight * 100)}%</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Section>

        <Section title="Findings">
          {result.findings.length === 0 ? (
            <p className="text-sm text-neutral-500">No findings were identified.</p>
          ) : (
            <ul className="space-y-3">
              {result.findings.map((f) => (
                <li key={f.id} className="text-sm">
                  <p className="font-semibold">
                    [{SEVERITY_LABEL[f.severity]}] {f.title}
                  </p>
                  <p className="text-neutral-700">{f.description}</p>
                  <p className="text-neutral-600">Recommendation: {f.recommendation}</p>
                  <p className="text-xs text-neutral-400">Source: {f.source}</p>
                </li>
              ))}
            </ul>
          )}
        </Section>

        <Section title="DNS">
          {result.dns.status === "ok" && result.dns.data ? (
            <div className="space-y-1 text-sm text-neutral-700">
              <p>A: {result.dns.data.a.join(", ") || "None"}</p>
              <p>AAAA: {result.dns.data.aaaa.join(", ") || "None"}</p>
              <p>MX: {result.dns.data.mx.map((m) => m.exchange).join(", ") || "None"}</p>
              <p>NS: {result.dns.data.ns.join(", ") || "None"}</p>
            </div>
          ) : (
            <p className="text-sm text-neutral-500">{result.dns.message ?? "Not available."}</p>
          )}
        </Section>

        <Section title="TLS">
          {result.tls.status === "ok" && result.tls.data ? (
            <div className="space-y-1 text-sm text-neutral-700">
              <p>Version: {result.tls.data.tlsVersion ?? "Unknown"}</p>
              <p>Issuer: {result.tls.data.issuer ?? "Unknown"}</p>
              <p>Expires: {formatDate(result.tls.data.validTo)}</p>
              <p>Authorized: {result.tls.data.authorized ? "Yes" : "No"}</p>
            </div>
          ) : (
            <p className="text-sm text-neutral-500">{result.tls.message ?? "Not available."}</p>
          )}
        </Section>

        <Section title="IP Intelligence">
          {result.ip.status === "ok" && result.ip.data ? (
            <div className="space-y-1 text-sm text-neutral-700">
              <p>IP: {result.ip.data.ip}</p>
              <p>Organization: {result.ip.data.organization ?? "Unknown"}</p>
              <p>Country: {result.ip.data.country ?? "Unknown"}</p>
            </div>
          ) : (
            <p className="text-sm text-neutral-500">{result.ip.message ?? "Not available."}</p>
          )}
        </Section>

        <Section title="Threat Intelligence">
          <div className="space-y-1 text-sm text-neutral-700">
            <p>
              VirusTotal:{" "}
              {result.threatIntelligence.virustotal.status === "ok" && result.threatIntelligence.virustotal.data
                ? `${result.threatIntelligence.virustotal.data.malicious} malicious / ${result.threatIntelligence.virustotal.data.totalEngines} engines`
                : (result.threatIntelligence.virustotal.message ?? "Unavailable")}
            </p>
            <p>
              AbuseIPDB:{" "}
              {result.threatIntelligence.abuseipdb.status === "ok" && result.threatIntelligence.abuseipdb.data
                ? `${result.threatIntelligence.abuseipdb.data.abuseConfidenceScore}% abuse confidence`
                : (result.threatIntelligence.abuseipdb.message ?? "Unavailable")}
            </p>
          </div>
        </Section>

        <Section title="Methodology">
          <p className="text-sm leading-relaxed text-neutral-700">
            The risk score is a weighted average of independently scored factors (TLS Security, HTTP Security
            Headers, DNS Configuration, Domain Reputation, IP Reputation, Threat Intelligence, and Configuration
            Findings). A factor is excluded from the average — never scored as safe or risky by default — when its
            underlying data is unavailable, such as a threat-intelligence provider with no configured API key.
            Score ranges: 0–19 Very Low, 20–39 Low, 40–59 Moderate, 60–79 High, 80–100 Critical.
          </p>
        </Section>

        <Section title="Disclaimer">
          <p className="text-sm leading-relaxed text-neutral-700">
            This report reflects a passive, non-destructive analysis performed at the time stated above. It is not
            a penetration test and does not guarantee the absence of vulnerabilities. SentinelScope is intended for
            authorized security assessment and educational use only.
          </p>
        </Section>
      </div>
    </div>
  );
}

import type { Metadata } from "next";
import Link from "next/link";
import { SiteNav } from "@/components/SiteNav";

export const metadata: Metadata = {
  title: "Methodology",
  description: "How SentinelScope's analysis pipeline and risk scoring actually work.",
};

const PIPELINE_STAGES = [
  { name: "Target Validation", detail: "Parses the input and rejects anything pointed at private, loopback, or reserved address space before any network call is made." },
  { name: "DNS Intelligence", detail: "Resolves A/AAAA/MX/NS/TXT/CNAME/SOA/CAA records plus a DMARC lookup, tolerant of any single record type being absent." },
  { name: "IP Intelligence", detail: "ASN, organization, and geolocation for the resolved address, plus a real reverse-DNS lookup." },
  { name: "TLS Analysis", detail: "A real TLS handshake against the target, pinned to its validated IP — certificate chain, protocol version, and expiry." },
  { name: "HTTP Analysis", detail: "One SSRF-safe fetch, redirect chain included, graded against six standard security headers." },
  { name: "Technology Detection", detail: "Passive fingerprinting of server, CDN, framework, and CMS from the same response — no separate probing requests." },
  { name: "Domain Intelligence", detail: "Registrar, registration date, and status via RDAP, the IETF-standard successor to WHOIS." },
  { name: "Threat Intelligence", detail: "VirusTotal and AbuseIPDB, only when their API keys are configured — otherwise reported as unavailable, never guessed." },
  { name: "Risk Engine", detail: "Combines every stage's real findings into one weighted score. See below." },
];

const RISK_FACTORS: [string, string, string][] = [
  ["TLS Security", "22%", "Certificate validity, expiry, protocol version"],
  ["HTTP Security Headers", "20%", "HSTS, CSP, X-Frame-Options, and four others"],
  ["DNS Configuration", "12%", "CAA, SPF, DMARC, nameserver redundancy"],
  ["Domain Reputation", "12%", "Registration age, RDAP status flags"],
  ["IP Reputation", "12%", "AbuseIPDB confidence score"],
  ["Threat Intelligence", "14%", "VirusTotal engine verdicts"],
  ["Configuration Findings", "8%", "Information disclosure, missing HTTPS redirect"],
];

export default function MethodologyPage() {
  return (
    <div className="relative min-h-screen">
      <SiteNav />
      <main className="mx-auto max-w-3xl px-6 pb-24 pt-6">
        <span className="text-xs font-semibold uppercase tracking-widest text-accent-400">Methodology</span>
        <h1 className="mt-2 text-4xl font-extrabold tracking-tight text-white">How the analysis actually works</h1>
        <p className="mt-4 text-base leading-relaxed text-base-400">
          SentinelScope runs nine pipeline stages against every target, entirely passively. Nothing here is
          simulated — each stage is a real DNS query, TLS handshake, HTTP request, or third-party API call,
          and its real completion is what drives the score below, not a template.
        </p>

        <section className="mt-12">
          <h2 className="mb-5 text-xs font-bold uppercase tracking-widest text-base-500">The Pipeline</h2>
          <ol className="space-y-4">
            {PIPELINE_STAGES.map((stage, i) => (
              <li key={stage.name} className="card-elevated flex gap-4 rounded-xl border border-base-700 bg-base-900/50 p-4">
                <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-accent-500/15 font-mono text-xs font-bold text-accent-400">
                  {i + 1}
                </span>
                <div>
                  <p className="font-semibold text-base-100">{stage.name}</p>
                  <p className="mt-0.5 text-sm text-base-400">{stage.detail}</p>
                </div>
              </li>
            ))}
          </ol>
        </section>

        <section className="mt-12">
          <h2 className="mb-2 text-xs font-bold uppercase tracking-widest text-base-500">Risk Score</h2>
          <p className="mb-5 text-sm leading-relaxed text-base-400">
            The score is a weighted average of the factors below. A factor whose data is unavailable — no
            threat-intel API key configured, a failed lookup — is excluded from the average entirely, and the
            remaining weights are renormalized. Missing data is never silently scored as safe or risky.
          </p>
          <div className="overflow-hidden rounded-xl border border-base-700">
            <table className="w-full text-sm">
              <thead>
                <tr className="bg-base-900/70 text-left text-xs uppercase tracking-wide text-base-500">
                  <th className="px-4 py-3 font-semibold">Factor</th>
                  <th className="px-4 py-3 font-semibold">Weight</th>
                  <th className="px-4 py-3 font-semibold">Signals</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-base-800">
                {RISK_FACTORS.map(([name, weight, signals]) => (
                  <tr key={name} className="bg-base-900/30">
                    <td className="px-4 py-3 font-medium text-base-100">{name}</td>
                    <td className="px-4 py-3 font-mono text-accent-400">{weight}</td>
                    <td className="px-4 py-3 text-base-400">{signals}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="mt-5 grid grid-cols-3 gap-2 sm:grid-cols-6">
            {[
              ["A+/A", "0–19", "#2dd4bf"],
              ["B", "20–39", "#60a5fa"],
              ["C", "40–59", "#eab308"],
              ["D", "60–79", "#f97316"],
              ["F", "80–100", "#ef4444"],
            ].map(([grade, range, color]) => (
              <div key={grade} className="rounded-lg border border-base-800 bg-base-900/40 px-2 py-3 text-center">
                <p className="text-lg font-extrabold" style={{ color }}>
                  {grade}
                </p>
                <p className="text-[11px] text-base-500">{range}</p>
              </div>
            ))}
          </div>
        </section>

        <section className="mt-12">
          <h2 className="mb-4 text-xs font-bold uppercase tracking-widest text-base-500">Security Commitments</h2>
          <ul className="space-y-3 text-sm leading-relaxed text-base-400">
            <li>
              <span className="font-semibold text-base-200">SSRF protection.</span> Every outbound request to a
              user-supplied target — and every redirect hop it follows — is resolved and validated against
              private, loopback, and reserved address space, then pinned to that validated IP for the actual
              connection.
            </li>
            <li>
              <span className="font-semibold text-base-200">No fabricated data.</span> A provider with no
              configured API key or a failed lookup is reported as &ldquo;Unavailable,&rdquo; never filled in with a
              guessed score.
            </li>
            <li>
              <span className="font-semibold text-base-200">No cross-visitor history.</span> A direct
              <code className="mx-1 rounded bg-base-800 px-1.5 py-0.5 font-mono text-xs">/analysis/[id]</code>
              link is shareable on purpose; the list of recent analyses on the homepage is not — it lives only
              in your own browser.
            </li>
            <li>
              <span className="font-semibold text-base-200">Passive only.</span> No exploitation, credential
              attacks, or denial of service — ever.
            </li>
          </ul>
        </section>

        <div className="mt-14">
          <Link
            href="/"
            className="inline-block rounded-xl bg-accent-500 px-6 py-3 text-sm font-bold text-base-950 transition hover:bg-accent-400"
          >
            ← Run an analysis
          </Link>
        </div>
      </main>
    </div>
  );
}

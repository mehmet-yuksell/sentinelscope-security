"use client";

import Link from "next/link";
import { useState } from "react";
import type { AnalysisResult } from "@/types/analysis";
import { RISK_LEVEL_COLOR, RISK_LEVEL_LABEL, displayGrade, displayScore, formatDate } from "@/utils/riskDisplay";
import { SiteNav } from "@/components/SiteNav";
import { OverviewPanel } from "./OverviewPanel";
import { DnsPanel } from "./DnsPanel";
import { EmailPanel } from "./EmailPanel";
import { TlsPanel } from "./TlsPanel";
import { HttpPanel } from "./HttpPanel";
import { IpPanel } from "./IpPanel";
import { DomainPanel } from "./DomainPanel";
import { ThreatIntelPanel } from "./ThreatIntelPanel";
import { FindingsPanel } from "./FindingsPanel";

const TABS = ["Overview", "DNS", "Email", "TLS", "HTTP", "IP", "Domain", "Threat Intelligence", "Findings"] as const;
type Tab = (typeof TABS)[number];

export function AnalysisDashboard({ result }: { result: AnalysisResult }) {
  const [tab, setTab] = useState<Tab>("Overview");
  const color = RISK_LEVEL_COLOR[result.riskLevel];

  const grade = displayGrade(result.riskScore, result.riskLevel);

  return (
    <div>
      <SiteNav />
      <div className="mx-auto max-w-5xl px-6 pb-12">
      <div
        className="card-elevated relative mb-8 flex flex-col gap-6 overflow-hidden rounded-2xl border border-base-700 bg-base-900/60 p-7 sm:flex-row sm:items-center sm:justify-between"
      >
        <div className="pointer-events-none absolute -right-24 -top-24 h-64 w-64 rounded-full blur-3xl" style={{ backgroundColor: `${color}14` }} />
        <div className="relative">
          <p className="text-xs font-semibold uppercase tracking-widest text-base-500">Target</p>
          <h1
            title={result.target}
            className="line-clamp-2 break-all text-2xl font-extrabold tracking-tight text-white sm:text-3xl"
          >
            {result.target}
          </h1>
          <p className="mt-1.5 text-xs text-base-500">
            Analyzed {formatDate(result.timestamp)} · {(result.durationMs / 1000).toFixed(1)}s pipeline duration
          </p>
        </div>
        <div className="relative flex items-center gap-5">
          <div className="flex items-center gap-3">
            <span className="text-3xl font-black" style={{ color }}>
              {grade}
            </span>
            <div className="text-right">
              <p className="text-xs font-semibold uppercase tracking-widest text-base-500">Risk Score</p>
              <p className="text-3xl font-extrabold tracking-tight" style={{ color }}>
                {displayScore(result.riskScore, result.riskLevel)}
                <span className="text-base font-medium text-base-500">/100</span>
              </p>
              <p className="text-xs font-bold uppercase tracking-wide" style={{ color }}>
                {RISK_LEVEL_LABEL[result.riskLevel]}
              </p>
            </div>
          </div>
          <Link
            href={`/analysis/${result.id}/report`}
            className="whitespace-nowrap rounded-xl border border-base-600 bg-base-900 px-5 py-2.5 text-sm font-semibold text-base-200 transition hover:border-accent-500 hover:text-accent-400"
          >
            Generate Report
          </Link>
        </div>
      </div>

      <div className="no-print mb-6 flex gap-1 overflow-x-auto rounded-xl border border-base-800 bg-base-900/50 p-1.5 scrollbar-thin">
        {TABS.map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`whitespace-nowrap rounded-lg px-4 py-2.5 text-sm font-semibold transition ${
              tab === t ? "glow-accent bg-accent-500 text-base-950" : "text-base-400 hover:bg-base-800/60 hover:text-base-100"
            }`}
          >
            {t}
          </button>
        ))}
      </div>

      <div className="animate-fadeIn">
        {tab === "Overview" && <OverviewPanel result={result} />}
        {tab === "DNS" && <DnsPanel dns={result.dns} />}
        {tab === "Email" && <EmailPanel email={result.email} />}
        {tab === "TLS" && <TlsPanel tls={result.tls} />}
        {tab === "HTTP" && <HttpPanel http={result.http} technologies={result.technologies} />}
        {tab === "IP" && <IpPanel ip={result.ip} />}
        {tab === "Domain" && <DomainPanel domain={result.domain} hostname={result.hostname} />}
        {tab === "Threat Intelligence" && <ThreatIntelPanel threatIntelligence={result.threatIntelligence} />}
        {tab === "Findings" && <FindingsPanel findings={result.findings} />}
      </div>
      </div>
    </div>
  );
}

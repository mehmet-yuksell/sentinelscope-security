import type { EmailSecurityInfo, ProviderResult } from "@/types/analysis";
import { ProviderStatusNotice } from "./ProviderStatusNotice";
import { summarizeDmarc, summarizeSpf } from "@/utils/emailDisplay";

function Card({ title, verdict, record, children }: { title: string; verdict: string; record: string | null; children?: React.ReactNode }) {
  return (
    <div className="card-elevated rounded-xl border border-base-700 bg-base-900/50 p-4">
      <h4 className="mb-1.5 text-xs font-bold uppercase tracking-widest text-accent-400">{title}</h4>
      <p className="text-sm font-medium text-base-100">{verdict}</p>
      {record && <p className="mt-2 break-all rounded-lg bg-base-950/60 px-3 py-2 font-mono text-xs text-base-300">{record}</p>}
      {children}
    </div>
  );
}

function Notes({ items }: { items: string[] }) {
  if (items.length === 0) return null;
  return (
    <ul className="mt-2 space-y-1 text-xs text-base-400">
      {items.map((item) => (
        <li key={item}>· {item}</li>
      ))}
    </ul>
  );
}

/** Missing on analyses stored before email checks existed — shown as unavailable, never guessed. */
export function EmailPanel({ email }: { email: ProviderResult<EmailSecurityInfo> | undefined }) {
  if (!email) {
    return <ProviderStatusNotice status="unavailable" message="This analysis was run before email security checks were added. Run a new analysis to see them." />;
  }
  if (email.status !== "ok" || !email.data) {
    return <ProviderStatusNotice status={email.status} message={email.message} />;
  }

  const { receivesMail, organizationalDomain, domain, spf, dmarc, mtaSts, tlsRptRecord } = email.data;

  const mtaStsVerdict = !mtaSts.record
    ? "Not published"
    : mtaSts.policyMode
      ? `mode: ${mtaSts.policyMode}${mtaSts.policyMaxAge !== null ? ` · max_age ${mtaSts.policyMaxAge}s` : ""}`
      : "Record published, policy unavailable";

  return (
    <div className="space-y-6">
      <p className="text-sm text-base-400">
        {receivesMail ? "This domain receives mail (MX records present)." : "This domain publishes no usable MX records, so it does not receive mail."}
        {organizationalDomain !== domain && (
          <>
            {" "}Organizational domain: <span className="font-mono text-base-200">{organizationalDomain}</span>.
          </>
        )}
      </p>

      <div className="grid gap-6 sm:grid-cols-2">
        <Card title="SPF" verdict={summarizeSpf(spf)} record={spf.record}>
          {spf.includes.length > 0 && <p className="mt-2 text-xs text-base-500">Includes: {spf.includes.join(", ")}</p>}
          <Notes items={spf.warnings} />
        </Card>

        <Card title="DMARC" verdict={summarizeDmarc(dmarc)} record={dmarc.record}>
          {dmarc.reportingUris.length > 0 && <p className="mt-2 break-all text-xs text-base-500">Aggregate reports: {dmarc.reportingUris.join(", ")}</p>}
        </Card>

        <Card title="MTA-STS" verdict={mtaStsVerdict} record={mtaSts.record}>
          <Notes items={mtaSts.policyError ? [mtaSts.policyError] : []} />
          {mtaSts.policyMode && <p className="mt-2 text-xs text-base-500">The policy host&apos;s certificate is not validated by this check.</p>}
        </Card>

        <Card title="TLS-RPT" verdict={tlsRptRecord ? "Published" : "Not published"} record={tlsRptRecord} />
      </div>

      <p className="text-xs text-base-500">
        DKIM is not checked: its keys are published under selectors chosen by each sender, which can&apos;t be discovered from DNS.
      </p>
    </div>
  );
}

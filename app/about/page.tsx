import type { Metadata } from "next";
import Link from "next/link";
import { SiteNav } from "@/components/SiteNav";

export const metadata: Metadata = {
  title: "About",
  description: "Why SentinelScope exists, who it's for, and who built it.",
};

const PROBLEMS = [
  {
    title: "Misconfigurations hide in plain sight",
    detail: "An expired certificate, a missing security header, a DNS record left wide open — all publicly visible to anyone who checks, and almost nobody does.",
  },
  {
    title: "Reputation data already exists, scattered",
    detail: "VirusTotal, AbuseIPDB, RDAP registries — the data is out there. SentinelScope queries it for you instead of five separate tabs.",
  },
  {
    title: "Raw data isn't a decision",
    detail: "A dump of TXT records or a certificate blob means nothing on its own. It only becomes useful once it's graded, weighted, and turned into a recommendation.",
  },
  {
    title: "Passive by design",
    detail: "You shouldn't have to touch a target to understand its exposure. Every check here is a read-only lookup — nothing is probed, guessed, or attacked.",
  },
];

const AUDIENCE = [
  "Developers sanity-checking their own deployment before it ships",
  "Small teams without a dedicated security function",
  "Students studying real-world DNS, TLS, and HTTP posture",
  "Anyone deciding whether an unfamiliar site looks legitimate",
];

export default function AboutPage() {
  return (
    <div className="relative min-h-screen">
      <SiteNav />
      <main className="mx-auto max-w-3xl px-6 pb-24 pt-6">
        <span className="text-xs font-semibold uppercase tracking-widest text-accent-400">About</span>
        <h1 className="mt-2 text-4xl font-extrabold tracking-tight text-white">
          See what&rsquo;s already public about your site
        </h1>
        <p className="mt-4 text-base leading-relaxed text-base-400">
          SentinelScope surfaces the same public security signals about a domain that a careful attacker — or a
          due-diligence checklist — would already see: certificate health, DNS hygiene, security headers, and
          reputation data. It never touches anything beyond what&rsquo;s already public, and it never guesses at
          what it can&rsquo;t verify.
        </p>

        <section className="mt-12">
          <h2 className="mb-5 text-xs font-bold uppercase tracking-widest text-base-500">Why This Matters</h2>
          <div className="grid gap-4 sm:grid-cols-2">
            {PROBLEMS.map((p) => (
              <div key={p.title} className="card-elevated rounded-xl border border-base-700 bg-base-900/50 p-5">
                <p className="font-semibold text-base-100">{p.title}</p>
                <p className="mt-1.5 text-sm leading-relaxed text-base-400">{p.detail}</p>
              </div>
            ))}
          </div>
        </section>

        <section className="mt-12">
          <h2 className="mb-5 text-xs font-bold uppercase tracking-widest text-base-500">Who It&rsquo;s For</h2>
          <ul className="space-y-2.5">
            {AUDIENCE.map((line) => (
              <li key={line} className="flex items-start gap-3 text-sm text-base-300">
                <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-accent-500" />
                {line}
              </li>
            ))}
          </ul>
        </section>

        <section className="mt-12">
          <h2 className="mb-5 text-xs font-bold uppercase tracking-widest text-base-500">Not Sure What a Result Means?</h2>
          <p className="text-sm leading-relaxed text-base-400">
            Every score, factor, and finding on this site is derived the same documented way — nothing is
            eyeballed or randomized. See exactly how the pipeline runs and how the risk score is calculated on the{" "}
            <Link href="/methodology" className="font-medium text-accent-400 underline underline-offset-2">
              Methodology
            </Link>{" "}
            page.
          </p>
        </section>

        <section className="card-elevated mt-12 rounded-2xl border border-base-700 bg-base-900/60 p-6">
          <h2 className="mb-3 text-xs font-bold uppercase tracking-widest text-base-500">Developer</h2>
          <div className="flex items-center gap-3.5">
            <span className="flex h-11 w-11 shrink-0 items-center justify-center rounded-full bg-accent-500/15 text-sm font-bold text-accent-400">
              MY
            </span>
            <div>
              <p className="font-semibold text-base-100">Mehmet Yüksel</p>
              <p className="text-sm text-base-400">Built SentinelScope end to end — pipeline, risk engine, and this dashboard.</p>
            </div>
          </div>
        </section>

        <section className="mt-12 rounded-xl border border-dashed border-base-700 bg-base-900/30 p-5">
          <p className="text-xs font-bold uppercase tracking-widest text-base-500">Educational &amp; authorized use only</p>
          <p className="mt-2 text-sm leading-relaxed text-base-400">
            SentinelScope performs passive, non-destructive lookups only — no exploitation, no credential attacks,
            no denial of service. Use it only against targets you own or are otherwise authorized to assess.
          </p>
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

import { AnalyzeForm } from "@/components/AnalyzeForm";
import { HistoryList } from "@/components/HistoryList";

export default function HomePage() {
  return (
    <main className="relative flex min-h-screen flex-col items-center overflow-hidden px-6 py-24">
      <div className="bg-grid pointer-events-none absolute inset-x-0 top-0 h-[560px]" />
      <div className="pointer-events-none absolute left-1/2 top-0 h-[420px] w-[720px] -translate-x-1/2 rounded-full bg-accent-500/10 blur-[120px]" />

      <div className="relative flex w-full max-w-3xl flex-col items-center gap-5 text-center">
        <span className="rounded-full border border-base-600 bg-base-900/80 px-3.5 py-1.5 text-[11px] font-medium uppercase tracking-[0.2em] text-accent-400 backdrop-blur">
          Passive Security Intelligence
        </span>
        <h1 className="text-glow text-5xl font-extrabold tracking-tight text-white sm:text-6xl">
          SENTINEL<span className="text-accent-400">SCOPE</span>
        </h1>
        <p className="text-xl font-medium text-base-200">Website &amp; Domain Threat Intelligence</p>
        <p className="max-w-xl text-sm leading-relaxed text-base-400">
          Analyze the security posture and public intelligence of a website, domain, or IP address —
          without ever attacking it.
        </p>
      </div>

      <div className="relative mt-14 w-full max-w-3xl">
        <AnalyzeForm />
      </div>

      <div className="relative mt-24 w-full max-w-2xl">
        <HistoryList />
      </div>

      <footer className="relative mt-20 max-w-xl text-center text-xs leading-relaxed text-base-600">
        SentinelScope performs passive, non-destructive reconnaissance only — DNS, TLS, HTTP, and
        public reputation lookups. It never attempts exploitation, credential attacks, or denial of
        service. Use it only against targets you are authorized to assess.
      </footer>
    </main>
  );
}

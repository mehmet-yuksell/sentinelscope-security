import { AnalyzeForm } from "@/components/AnalyzeForm";
import { HistoryList } from "@/components/HistoryList";

export default function HomePage() {
  return (
    <main className="flex min-h-screen flex-col items-center px-6 py-20">
      <div className="flex w-full max-w-3xl flex-col items-center gap-4 text-center">
        <span className="rounded-full border border-base-700 px-3 py-1 text-xs uppercase tracking-widest text-base-500">
          Passive Security Intelligence
        </span>
        <h1 className="text-4xl font-bold tracking-tight text-base-50 sm:text-5xl">SENTINELSCOPE</h1>
        <p className="text-lg text-base-300">Website &amp; Domain Threat Intelligence</p>
        <p className="max-w-xl text-sm text-base-400">
          Analyze the security posture and public intelligence of a website, domain, or IP address —
          without ever attacking it.
        </p>
      </div>

      <div className="mt-12 w-full max-w-3xl">
        <AnalyzeForm />
      </div>

      <div className="mt-20 w-full max-w-2xl">
        <HistoryList />
      </div>

      <footer className="mt-20 max-w-xl text-center text-xs leading-relaxed text-base-600">
        SentinelScope performs passive, non-destructive reconnaissance only — DNS, TLS, HTTP, and
        public reputation lookups. It never attempts exploitation, credential attacks, or denial of
        service. Use it only against targets you are authorized to assess.
      </footer>
    </main>
  );
}

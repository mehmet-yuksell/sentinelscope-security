import Link from "next/link";

export default function NotFound() {
  return (
    <main className="flex min-h-screen flex-col items-center justify-center gap-4 px-6 text-center">
      <p className="text-xs uppercase tracking-widest text-base-500">404</p>
      <h1 className="text-2xl font-bold text-base-100">Analysis not found</h1>
      <p className="max-w-sm text-sm text-base-400">
        This analysis may have expired or the link is incorrect. Start a new scan from the homepage.
      </p>
      <Link href="/" className="rounded-lg bg-accent-500 px-5 py-2.5 text-sm font-semibold text-base-950 hover:bg-accent-400">
        Back to SentinelScope
      </Link>
    </main>
  );
}

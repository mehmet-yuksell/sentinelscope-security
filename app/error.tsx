"use client"; // Error boundaries must be Client Components

import Link from "next/link";

/**
 * Shown when a page throws — e.g. the result store is unreachable while
 * loading /analysis/[id]. Server-side details stay in the server logs; the
 * digest lets an operator match this screen to the corresponding log entry.
 */
export default function Error({ error, retry }: { error: unknown; retry: () => void }) {
  const digest = error instanceof Error && "digest" in error ? String((error as Error & { digest?: string }).digest ?? "") : "";

  return (
    <main className="flex min-h-screen flex-col items-center justify-center gap-4 px-6 text-center">
      <p className="text-xs uppercase tracking-widest text-base-500">Error</p>
      <h1 className="text-2xl font-bold text-base-100">Something went wrong</h1>
      <p className="max-w-sm text-sm text-base-400">
        This page could not be loaded right now. Try again, or start a new scan from the homepage.
      </p>
      <div className="flex gap-3">
        <button
          type="button"
          onClick={() => retry()}
          className="rounded-lg bg-accent-500 px-5 py-2.5 text-sm font-semibold text-base-950 hover:bg-accent-400"
        >
          Try again
        </button>
        <Link href="/" className="rounded-lg border border-base-600 px-5 py-2.5 text-sm font-semibold text-base-200 hover:border-accent-500">
          Back to SentinelScope
        </Link>
      </div>
      {digest && <p className="font-mono text-[11px] text-base-600">Reference: {digest}</p>}
    </main>
  );
}

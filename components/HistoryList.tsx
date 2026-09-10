"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import type { HistoryEntry } from "@/types/analysis";
import { RISK_LEVEL_COLOR, formatRelativeTime } from "@/utils/riskDisplay";
import { getRecentAnalyses } from "@/utils/clientHistory";

/**
 * Shows only THIS browser's own recent analyses, read from localStorage —
 * never fetched from the server, so no visitor can see another visitor's
 * queried targets.
 */
export function HistoryList() {
  const [entries, setEntries] = useState<HistoryEntry[]>([]);

  useEffect(() => {
    // localStorage is only readable client-side and would mismatch the
    // server-rendered markup if read during render, so this intentionally
    // reads once after mount rather than during the initial render.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setEntries(getRecentAnalyses());
  }, []);

  if (entries.length === 0) return null;

  return (
    <div className="w-full max-w-2xl">
      <h2 className="mb-3 text-xs font-bold uppercase tracking-widest text-base-500">Your Recent Analyses</h2>
      <ul className="card-elevated divide-y divide-base-800 overflow-hidden rounded-2xl border border-base-700 bg-base-900/50">
        {entries.map((entry) => (
          <li key={entry.id}>
            <Link
              href={`/analysis/${entry.id}`}
              className="flex items-center justify-between gap-4 px-5 py-4 transition hover:bg-base-800/50"
            >
              <div className="min-w-0">
                <p className="truncate font-mono text-sm font-medium text-base-100">{entry.target}</p>
                <p className="text-xs text-base-500">{formatRelativeTime(entry.timestamp)}</p>
              </div>
              <div
                className="flex items-center gap-1.5 rounded-full px-3 py-1 text-sm font-bold"
                style={{ color: RISK_LEVEL_COLOR[entry.riskLevel], backgroundColor: `${RISK_LEVEL_COLOR[entry.riskLevel]}1a` }}
              >
                {entry.riskScore}
                <span className="text-xs font-medium text-base-500">/100</span>
              </div>
            </Link>
          </li>
        ))}
      </ul>
      <p className="mt-2 text-[11px] text-base-600">Only visible in this browser — never shared with other visitors.</p>
    </div>
  );
}

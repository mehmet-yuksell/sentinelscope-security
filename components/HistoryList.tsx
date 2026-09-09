"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import type { HistoryEntry } from "@/types/analysis";
import { RISK_LEVEL_COLOR, formatRelativeTime } from "@/utils/riskDisplay";

export function HistoryList() {
  const [entries, setEntries] = useState<HistoryEntry[] | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetch("/api/history")
      .then((res) => (res.ok ? res.json() : []))
      .then((data: HistoryEntry[]) => {
        if (!cancelled) setEntries(data);
      })
      .catch(() => {
        if (!cancelled) setEntries([]);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  if (!entries || entries.length === 0) return null;

  return (
    <div className="w-full max-w-2xl">
      <h2 className="mb-3 text-xs font-bold uppercase tracking-widest text-base-500">Recent Analyses</h2>
      <ul className="card-elevated divide-y divide-base-800 overflow-hidden rounded-2xl border border-base-700 bg-base-900/50">
        {entries.slice(0, 6).map((entry) => (
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
    </div>
  );
}

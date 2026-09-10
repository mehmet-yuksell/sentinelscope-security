import type { AnalysisResult } from "@/types/analysis";

/**
 * Stores individual analyses by id so a direct /analysis/[id] link works
 * for anyone it's shared with. Deliberately has no "list everything"
 * method — there is no cross-visitor history feature. Each visitor's own
 * recent-analyses list lives in their browser's localStorage
 * (see components/HistoryList.tsx) and is never sent to or stored on the
 * server, so one visitor's queries are never visible to another.
 */
export interface AnalysisStore {
  saveAnalysis(result: AnalysisResult): Promise<void>;
  getAnalysis(id: string): Promise<AnalysisResult | null>;
}

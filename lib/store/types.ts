import type { AnalysisResult, HistoryEntry } from "@/types/analysis";

export interface AnalysisStore {
  saveAnalysis(result: AnalysisResult): Promise<void>;
  getAnalysis(id: string): Promise<AnalysisResult | null>;
  listHistory(limit?: number): Promise<HistoryEntry[]>;
}

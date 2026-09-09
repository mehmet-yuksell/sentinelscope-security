import { notFound } from "next/navigation";
import type { Metadata } from "next";
import { getAnalysis } from "@/lib/store";
import { AnalysisDashboard } from "@/components/dashboard/AnalysisDashboard";

interface PageProps {
  params: Promise<{ id: string }>;
}

export async function generateMetadata({ params }: PageProps): Promise<Metadata> {
  const { id } = await params;
  const result = await getAnalysis(id);
  return { title: result ? `${result.target} — Analysis` : "Analysis Not Found" };
}

export default async function AnalysisPage({ params }: PageProps) {
  const { id } = await params;
  const result = await getAnalysis(id);
  if (!result) notFound();

  return <AnalysisDashboard result={result} />;
}

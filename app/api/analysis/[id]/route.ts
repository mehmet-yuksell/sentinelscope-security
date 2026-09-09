import { NextRequest, NextResponse } from "next/server";
import { getAnalysis } from "@/lib/store";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(_request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const result = await getAnalysis(id);
  if (!result) {
    return NextResponse.json({ error: "Analysis not found." }, { status: 404 });
  }
  return NextResponse.json(result);
}

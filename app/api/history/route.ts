import { NextResponse } from "next/server";
import { listHistory } from "@/lib/store";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  const history = await listHistory(25);
  return NextResponse.json(history);
}

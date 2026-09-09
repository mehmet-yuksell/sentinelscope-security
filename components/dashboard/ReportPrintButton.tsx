"use client";

export function ReportPrintButton() {
  return (
    <button
      onClick={() => window.print()}
      className="no-print rounded-lg bg-neutral-900 px-5 py-2.5 text-sm font-semibold text-white transition hover:bg-neutral-700"
    >
      Print / Save as PDF
    </button>
  );
}

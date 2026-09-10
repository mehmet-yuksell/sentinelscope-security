import Link from "next/link";
import { Logo } from "./Logo";

/**
 * A persistent top nav across the real pages (scanner, methodology) — the
 * thing that makes this read as a product with more than one page, not a
 * single lonely tool page. Wraps onto a second row on narrow screens rather
 * than hiding content or squeezing it into one cramped line.
 */
export function SiteNav() {
  return (
    <header className="no-print relative z-10 flex flex-wrap items-center gap-x-4 gap-y-3 px-5 py-4 sm:justify-between sm:px-10 sm:py-5">
      <Link href="/" className="transition hover:opacity-80">
        <Logo size={24} />
      </Link>
      <nav className="flex flex-wrap items-center gap-3 text-sm font-medium text-base-400 sm:gap-6">
        <Link href="/" className="hidden transition hover:text-base-100 sm:inline">
          Scanner
        </Link>
        <Link href="/methodology" className="transition hover:text-base-100">
          Methodology
        </Link>
        <Link
          href="/about"
          className="rounded-full border border-base-700 bg-base-900/60 px-3.5 py-1.5 text-xs font-semibold text-base-200 transition hover:border-accent-500 hover:text-accent-400"
        >
          About
        </Link>
      </nav>
    </header>
  );
}

import Link from "next/link";
import { Logo } from "./Logo";

/**
 * A persistent top nav across the real pages (scanner, methodology) — the
 * thing that makes this read as a product with more than one page, not a
 * single lonely tool page.
 */
export function SiteNav() {
  return (
    <header className="no-print relative z-10 flex items-center justify-between px-6 py-5 sm:px-10">
      <Link href="/" className="transition hover:opacity-80">
        <Logo size={26} />
      </Link>
      <nav className="flex items-center gap-6 text-sm font-medium text-base-400">
        <Link href="/" className="transition hover:text-base-100">
          Scanner
        </Link>
        <Link href="/methodology" className="transition hover:text-base-100">
          Methodology
        </Link>
        <div className="flex items-center gap-2.5 rounded-full border border-base-700 bg-base-900/60 py-1.5 pl-1.5 pr-4">
          <span className="flex h-6 w-6 items-center justify-center rounded-full bg-accent-500/15 text-[10px] font-bold text-accent-400">
            MY
          </span>
          <span className="leading-tight">
            <span className="block text-[9px] uppercase tracking-widest text-base-500">Developer</span>
            <span className="block text-xs font-semibold text-base-200">Mehmet Yüksel</span>
          </span>
        </div>
      </nav>
    </header>
  );
}

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
        <a
          href="https://github.com/mehmetyuksell/sentinelscope"
          target="_blank"
          rel="noreferrer"
          className="rounded-lg border border-base-700 px-3.5 py-1.5 text-xs font-semibold text-base-200 transition hover:border-accent-500 hover:text-accent-400"
        >
          GitHub
        </a>
      </nav>
    </header>
  );
}

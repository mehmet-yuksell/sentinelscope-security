interface LogoProps {
  size?: number;
  showWordmark?: boolean;
  className?: string;
}

/**
 * A radar/scope mark inside a shield outline — the site's one piece of
 * distinct visual identity, used everywhere the wordmark appears instead of
 * relying on typography alone.
 */
export function Logo({ size = 28, showWordmark = true, className = "" }: LogoProps) {
  return (
    <span className={`inline-flex items-center gap-2.5 ${className}`}>
      <svg width={size} height={size} viewBox="0 0 32 32" fill="none" aria-hidden="true">
        <path
          d="M16 2 L28 7 V15 C28 22.5 22.8 27.8 16 30 C9.2 27.8 4 22.5 4 15 V7 L16 2Z"
          stroke="#2dd4bf"
          strokeWidth="1.6"
          fill="rgba(45,212,191,0.08)"
        />
        <circle cx="16" cy="15.5" r="6" stroke="#2dd4bf" strokeWidth="1.4" fill="none" />
        <circle cx="16" cy="15.5" r="1.6" fill="#2dd4bf" />
        <path d="M16 9.5 V6.5 M16 21.5 V19.5 M22 15.5 H24.5 M7.5 15.5 H10" stroke="#2dd4bf" strokeWidth="1.4" strokeLinecap="round" />
      </svg>
      {showWordmark && (
        <span className="text-lg font-extrabold tracking-tight text-white">
          SENTINEL<span className="text-accent-400">SCOPE</span>
        </span>
      )}
    </span>
  );
}

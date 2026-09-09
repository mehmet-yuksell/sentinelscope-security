import type { HttpInfo, ProviderResult, TechnologyEntry } from "@/types/analysis";
import { ProviderStatusNotice } from "./ProviderStatusNotice";
import { HEADER_STATUS_COLOR, HEADER_STATUS_ICON } from "@/utils/riskDisplay";

interface HttpPanelProps {
  http: ProviderResult<HttpInfo>;
  technologies: TechnologyEntry[];
}

export function HttpPanel({ http, technologies }: HttpPanelProps) {
  if (http.status !== "ok" || !http.data) {
    return <ProviderStatusNotice status={http.status} message={http.message} />;
  }

  const h = http.data;

  return (
    <div className="space-y-6">
      <div className="space-y-1 rounded-lg border border-base-700 bg-base-900/40 p-4 text-sm text-base-300">
        <p>
          <span className="text-base-500">Final URL:</span> <span className="font-mono">{h.finalUrl}</span>
        </p>
        <p>
          <span className="text-base-500">Status Code:</span> {h.statusCode}
        </p>
        {h.redirected && (
          <p className="break-all">
            <span className="text-base-500">Redirect Chain:</span> {[...h.redirectChain, h.finalUrl].join(" → ")}
          </p>
        )}
        {h.server && (
          <p>
            <span className="text-base-500">Server:</span> {h.server}
          </p>
        )}
      </div>

      <div>
        <h4 className="mb-2 text-xs font-semibold uppercase tracking-widest text-base-500">HTTP Security Headers</h4>
        <ul className="divide-y divide-base-800 rounded-lg border border-base-800">
          {h.securityHeaders.map((check) => (
            <li key={check.header} className="flex items-start justify-between gap-4 px-4 py-3">
              <div className="min-w-0">
                <p className="font-mono text-sm text-base-100">{check.header}</p>
                <p className="text-xs text-base-500">{check.description}</p>
                {check.value && <p className="mt-1 break-all font-mono text-xs text-base-400">{check.value}</p>}
              </div>
              <span className="shrink-0 text-lg font-bold" style={{ color: HEADER_STATUS_COLOR[check.status] }}>
                {HEADER_STATUS_ICON[check.status]}
              </span>
            </li>
          ))}
        </ul>
      </div>

      {technologies.length > 0 && (
        <div>
          <h4 className="mb-2 text-xs font-semibold uppercase tracking-widest text-base-500">Technology Detected</h4>
          <div className="grid gap-2 sm:grid-cols-2">
            {technologies.map((tech) => (
              <div key={`${tech.category}-${tech.name}`} className="rounded-lg border border-base-800 bg-base-900/40 px-3 py-2">
                <p className="text-xs uppercase tracking-widest text-base-500">{tech.category}</p>
                <p className="text-sm text-base-100">
                  {tech.name} <span className="text-xs text-base-500">({tech.confidence} confidence)</span>
                </p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

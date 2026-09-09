import type { ProviderStatus } from "@/types/analysis";
import { PROVIDER_STATUS_LABEL } from "@/utils/riskDisplay";

interface ProviderStatusNoticeProps {
  status: ProviderStatus;
  message?: string;
}

/** Shown whenever a provider has no usable data — never replaced with fabricated results. */
export function ProviderStatusNotice({ status, message }: ProviderStatusNoticeProps) {
  return (
    <div className="rounded-2xl border border-dashed border-base-700 bg-base-900/40 px-4 py-10 text-center">
      <p className="text-sm font-bold text-base-300">{PROVIDER_STATUS_LABEL[status]}</p>
      {message && <p className="mx-auto mt-1.5 max-w-sm text-xs leading-relaxed text-base-500">{message}</p>}
    </div>
  );
}

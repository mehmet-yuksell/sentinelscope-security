import { getDomain } from "tldts";

/**
 * The registered ("organizational") domain a hostname belongs to, per the
 * ICANN section of the Public Suffix List: www.example.co.uk -> example.co.uk.
 * Registration data (RDAP) and DMARC policy discovery both live at this
 * level, not at arbitrary subdomains. Falls back to the hostname itself when
 * none can be derived (e.g. the hostname is itself a public suffix).
 */
export function getRegistrableDomain(hostname: string): string {
  return getDomain(hostname, { allowPrivateDomains: false }) ?? hostname;
}

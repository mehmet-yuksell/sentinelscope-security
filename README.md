# SentinelScope

**Website & Domain Threat Intelligence Platform**

SentinelScope analyzes the public security posture of a website, domain, or
IP address — DNS, TLS, HTTP security headers, IP/domain intelligence, and
threat-intelligence reputation — and turns it into a single risk score with
concrete, evidence-backed findings.

It is a passive reconnaissance tool, not an attack tool. See
[Security](#security) and [Responsible Use](#responsible-use).

---

## Overview

Paste in `example.com`, `https://example.com`, or an IP address, and
SentinelScope runs a real backend pipeline against it: resolving DNS
records, opening an actual TLS handshake, fetching and grading HTTP
security headers, looking up IP/ASN and domain registration data, querying
threat-intelligence providers (when configured), and finally computing a
weighted risk score from everything it found. Every screen in the dashboard
reflects a real lookup — a provider with nothing to report says so
explicitly rather than showing a fabricated value.

## Features

- **DNS Intelligence** — A, AAAA, MX, NS, TXT, CNAME, SOA, CAA, and a
  targeted DMARC lookup
- **TLS Analysis** — real TLS handshake: protocol version, issuer,
  validity window, SANs, trust/authorization status
- **HTTP Security Headers** — HSTS, CSP, X-Content-Type-Options,
  X-Frame-Options, Referrer-Policy, Permissions-Policy, each graded
  pass/warning/missing
- **IP Intelligence** — ASN, organization/ISP, geolocation, reverse DNS
- **Domain Intelligence** — registrar, registration/expiry dates,
  nameservers, domain age via RDAP
- **Threat Intelligence** — VirusTotal and AbuseIPDB reputation (when API
  keys are configured)
- **Technology Detection** — passive fingerprinting of web server, CDN,
  framework, CMS, and analytics from headers/HTML markers
- **Risk Scoring** — a transparent, weighted-factor risk engine (see
  [Risk Methodology](#risk-methodology))
- **Security Findings** — each finding carries severity, evidence, and a
  concrete recommendation
- **Report Generation** — a print-friendly report per analysis
- **Analysis History** — recent scans, persisted locally

## Architecture

```text
                     Browser (Next.js App Router UI)
                                 |
                       POST /api/analyze/stream (SSE)
                                 |
                     Rate Limiter  +  Result Cache
                                 |
                       Analysis Orchestrator
                                 |
   +---------+---------+---------+---------+---------+---------+
   |  DNS    |   IP    |  TLS    |  HTTP   | Domain  |  Threat  |
   | Service | Service | Service | Service | Service |  Intel   |
   +---------+---------+---------+---------+---------+---------+
                                 |
                       Technology Detection
                                 |
                          Risk Engine
                                 |
                     Normalized AnalysisResult
                                 |
                    File-backed store (history)
```

Every outbound connection to a **user-supplied** target — the initial
request and every HTTP redirect hop — is routed through
`lib/net/safeRequest.ts`, which resolves and validates the destination
against private/reserved address space before connecting (see
[Security](#security)). Threat-intelligence and IP-geolocation calls go to
fixed, trusted third-party APIs and are not subject to that check.

## Tech Stack

| Layer      | Choice                                                |
| ---------- | ------------------------------------------------------ |
| Framework  | Next.js 16 (App Router), TypeScript (strict)           |
| UI         | Tailwind CSS, Recharts                                 |
| Validation | Zod                                                     |
| Backend    | Next.js Route Handlers (Node runtime), Node core `dns`/`tls`/`http`/`https` |
| Storage    | Lightweight JSON file store (`lib/store.ts`) — swappable for Postgres/SQLite |
| Testing    | Vitest                                                  |
| Container  | Docker (multi-stage, standalone output)                |
| CI         | GitHub Actions                                          |

## Screenshots

Add screenshots of the landing page and the analysis dashboard here
(`docs/screenshots/`) before publishing — the Overview tab (risk gauge +
Security DNA radar) and the Findings tab make the strongest first
impression.

## How It Works

1. **Target Validation** — the input is parsed as a domain, URL, or IP and
   checked against reserved/private address space (`lib/validation/target.ts`).
2. **DNS Intelligence** — standard record types are resolved in parallel,
   tolerating missing record types (`services/dns`).
3. **IP Intelligence** — the resolved IP is looked up for ASN/org/geo via a
   free keyless API, plus a real reverse-DNS lookup (`services/ip`).
4. **TLS Analysis** — a real TLS socket is opened against the resolved,
   validated IP; the certificate chain is inspected (`services/tls`).
5. **HTTP Analysis** — a single SSRF-safe fetch retrieves headers and body;
   headers are graded and the body is reused for technology detection
   (`services/http`, `services/technology`).
6. **Domain Intelligence** — registration data is fetched via RDAP
   (`services/domain`).
7. **Threat Intelligence** — VirusTotal and AbuseIPDB are queried in
   parallel if their API keys are configured (`services/threat-intelligence`).
8. **Risk Engine** — each factor is independently scored 0–100; factors
   with no usable data are excluded from the weighted average rather than
   defaulting to "safe" (`services/risk-engine`).

Each stage's real completion is streamed to the browser over
Server-Sent Events (`/api/analyze/stream`) as it finishes, so the pipeline
UI reflects actual backend timing — not a fake loading animation.

## Security

- **SSRF protection.** `lib/security/ssrf.ts` blocks loopback, RFC1918
  private ranges, link-local (including the `169.254.169.254` cloud
  metadata address), carrier-grade NAT, multicast, and their IPv6
  equivalents. `lib/net/safeRequest.ts` re-validates **every redirect hop**
  and pins each connection to its validated IP (not just the hostname) to
  close the DNS-rebinding time-of-check/time-of-use gap.
- **Input validation.** Only `http`/`https` schemes and ports 80/443 are
  permitted; URLs with embedded credentials are rejected.
- **Rate limiting.** `lib/rateLimit.ts` limits analyze requests per client
  IP (`RATE_LIMIT_MAX` / `RATE_LIMIT_WINDOW_MS`).
- **Timeouts & response caps.** Every outbound socket has a connect/read
  timeout, a capped redirect count, and a maximum response size.
- **Caching.** Identical targets are served from an in-memory TTL cache
  (`ANALYSIS_CACHE_TTL_MS`) to reduce load on both this server and upstream
  providers.
- **Secrets never reach the client.** Third-party API keys live in
  server-side environment variables and are read only inside
  `services/threat-intelligence`.

## Risk Methodology

The risk score is a weighted average of independently scored 0–100 risk
factors:

| Factor                  | Weight |
| ------------------------ | ------ |
| TLS Security             | 22%    |
| HTTP Security Headers    | 20%    |
| Threat Intelligence      | 14%    |
| DNS Configuration        | 12%    |
| Domain Reputation        | 12%    |
| IP Reputation            | 12%    |
| Configuration Findings   | 8%     |

A factor is **excluded from the average** — not scored as safe or risky —
when its underlying data is unavailable (e.g. no `VIRUSTOTAL_API_KEY`
configured, or a failed lookup). This means the score always reflects only
the evidence actually gathered.

```text
Risk Score = weighted average of applicable factor scores

0–19   Very Low
20–39  Low
40–59  Moderate
60–79  High
80–100 Critical
```

See `services/risk-engine/index.ts` for the full scoring logic and the
exact evidence that drives each factor.

## Installation

```bash
git clone https://github.com/mehmetyuksell/sentinelscope.git
cd sentinelscope
npm install
cp .env.example .env
npm run dev
```

Open http://localhost:3000.

### Environment Variables

All threat-intelligence keys are optional. Without them, SentinelScope
still runs the full DNS/TLS/HTTP/IP/domain pipeline and clearly labels
threat-intelligence as "Unavailable" rather than faking a result.

| Variable                 | Required | Purpose                                  |
| ------------------------- | -------- | ----------------------------------------- |
| `VIRUSTOTAL_API_KEY`      | No       | Domain/IP reputation via VirusTotal       |
| `ABUSEIPDB_API_KEY`       | No       | IP abuse reputation via AbuseIPDB         |
| `URLSCAN_API_KEY`         | No       | Reserved for future URL-scan integration  |
| `RATE_LIMIT_MAX`          | No       | Requests per IP per window (default `10`) |
| `RATE_LIMIT_WINDOW_MS`    | No       | Rate-limit window in ms (default `60000`) |
| `ANALYSIS_CACHE_TTL_MS`   | No       | Result cache TTL in ms (default `300000`) |

## Docker

```bash
docker compose up --build
```

This builds the multi-stage image (Next.js standalone output) and serves
the app on http://localhost:3000, persisting analysis history to a named
volume. Pass API keys via a `.env` file in the project root — Compose
reads it automatically — or your shell environment.

## Testing

```bash
npm test
```

- **Unit tests** — target/URL validation and SSRF address-range checks
  (`tests/unit/target.test.ts`, `tests/unit/ssrf.test.ts`), HTTP
  security-header grading (`tests/unit/http-headers.test.ts`), and risk
  engine scoring/finding logic (`tests/unit/risk-engine.test.ts`).
- **Integration tests** — the `/api/analyze` route handler, covering
  validation errors, the success path, cache-hit behavior, error mapping,
  and rate limiting (`tests/integration/analyze-route.test.ts`), with the
  orchestrator mocked so tests don't depend on live network access.

## Project Structure

```text
sentinelscope/
├── app/                      # Next.js App Router pages & API routes
│   ├── api/
│   │   ├── analyze/          # POST /api/analyze (JSON) and /stream (SSE)
│   │   ├── analysis/[id]/    # GET a stored analysis
│   │   └── history/          # GET recent analyses
│   └── analysis/[id]/        # Dashboard + print-friendly report pages
├── components/                # UI components (dashboard/, form, pipeline)
├── lib/
│   ├── security/ssrf.ts       # Reserved-address-space checks
│   ├── net/safeRequest.ts     # SSRF-safe HTTP client with redirect pinning
│   ├── validation/target.ts   # Target parsing/validation
│   ├── rateLimit.ts, cache.ts, store.ts, analyzeShared.ts
├── services/
│   ├── dns/ tls/ http/ ip/ domain/ technology/ threat-intelligence/
│   ├── risk-engine/            # Weighted scoring + finding generation
│   └── orchestrator.ts         # Ties every stage together
├── types/analysis.ts           # The normalized AnalysisResult data model
├── tests/unit/, tests/integration/
├── Dockerfile, docker-compose.yml
└── .github/workflows/ci.yml
```

## Limitations

- **Threat intelligence requires API keys.** Without `VIRUSTOTAL_API_KEY`
  / `ABUSEIPDB_API_KEY`, those panels report "Unavailable" — this is
  intentional (see [Real Data Priority](#real-data-priority) below), not a
  bug.
- **RDAP/WHOIS coverage varies by TLD.** Some registries don't expose full
  RDAP data; the Domain tab degrades gracefully when that happens.
- **The `isDatacenter` flag is a heuristic** derived from the IP
  organization string, not an authoritative classification.
- **History storage is a single JSON file**, sufficient for a
  single-instance deployment/demo, not a production-scale datastore.
- **No authentication.** This is a public demo tool by design; add auth
  before deploying it as anything more than a personal/portfolio instance.

### Real Data Priority

1. Real API / real local analysis
2. A clearly labeled "Unavailable" or "Not Applicable" state
3. Never: a fabricated score, reputation verdict, or vulnerability

## Responsible Use

SentinelScope performs **passive, non-destructive** reconnaissance only:
DNS resolution, TLS handshakes, HTTP header inspection, and public
reputation lookups. It never attempts exploitation, credential attacks,
brute forcing, or denial of service, and outbound requests to
user-supplied targets are restricted to public address space (see
[Security](#security)). Use it only against targets you are authorized to
assess.

## Author

**Mehmet Yüksel**

GitHub: [github.com/mehmetyuksell](https://github.com/mehmetyuksell)

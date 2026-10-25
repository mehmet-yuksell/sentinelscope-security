# Changelog

All notable changes to SentinelScope are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-10-26

First tagged release.

### Added

- Passive analysis pipeline for a domain, URL, or IP address: target
  validation, DNS, IP intelligence, TLS, HTTP, technology detection, domain
  registration (RDAP), threat intelligence, and risk scoring.
- DNS intelligence: A, AAAA, MX, NS, TXT, CNAME, SOA, CAA and DMARC records,
  with CAA inherited from parent domains as RFC 8659 specifies.
- TLS analysis from a real handshake: negotiated protocol, issuer, validity
  window, SANs, trust status, and self-signed detection.
- Grading of six HTTP security headers (HSTS, CSP, X-Content-Type-Options,
  X-Frame-Options, Referrer-Policy, Permissions-Policy).
- Passive technology fingerprinting from response headers and HTML markers.
- Optional VirusTotal and AbuseIPDB reputation lookups.
- Weighted risk engine over seven factors that excludes factors without data
  and reports "Insufficient Data" when nothing could be measured.
- Live pipeline progress over Server-Sent Events.
- Analysis dashboard, shareable `/analysis/[id]` links, and a
  print-friendly report.
- Per-browser recent-analyses history kept in `localStorage` only.
- JSON file store for single-process deployments and Upstash Redis store
  and rate limiter for serverless deployments.
- Docker image (multi-stage, standalone output) and Docker Compose setup.
- CI on GitHub Actions (lint, type check, tests, build, production
  dependency audit) and Dependabot updates.

### Security

- SSRF guard that resolves every user-supplied target and redirect hop,
  rejects private, reserved, and cloud-metadata address space (IPv4, IPv6,
  and IPv6 transition forms such as 6to4, Teredo, NAT64, and
  IPv4-compatible/mapped addresses), and pins each connection to the
  validated IP.
- Analysis restricted to `http`/`https` on ports 80 and 443, enforced at
  validation, per HTTP hop, and in the TLS stage.
- Per-client rate limiting, response size caps, redirect limits, and a hard
  per-hop deadline on outbound HTTP requests.
- Next.js upgraded to 16.4.3 and Zod to v4 to resolve published advisories.

### Fixed

Issues found and fixed in a pre-release audit:

- HTTP response bodies were never captured, so body-based technology
  detection never matched.
- Outbound HTTP requests that timed out or stalled never settled, hanging
  the analysis.
- An analysis where nothing could be measured was shown as grade A+ /
  "Very Low Risk"; it is now reported as "Insufficient Data", and the
  Security DNA chart no longer plots unmeasured factors as 0% health.
- Subdomains with their own address records were wrongly reported as having
  no CAA record.
- A URL with a non-standard port (e.g. `:22`) made the TLS stage connect to
  that port.

[Unreleased]: https://github.com/mehmet-yuksell/sentinelscope-security/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/mehmet-yuksell/sentinelscope-security/releases/tag/v1.0.0

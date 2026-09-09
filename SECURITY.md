# Security Policy

SentinelScope is a portfolio / educational project, but it is built with
production-minded security practices and welcomes scrutiny.

## Scope and Intent

SentinelScope performs **passive, non-destructive** reconnaissance only:
DNS resolution, TLS handshakes, HTTP header inspection, and public
reputation API lookups. It does not perform exploitation, brute force,
credential attacks, or denial-of-service testing, and it is not designed to.

## Reporting a Vulnerability

If you find a security issue in this project (for example, a bypass of the
SSRF protections in `lib/security/ssrf.ts` or `lib/net/safeRequest.ts`),
please open a private report via GitHub's "Report a vulnerability" feature
on this repository, or contact the maintainer directly rather than opening
a public issue.

Please include:

- A description of the issue and its potential impact
- Steps to reproduce (a target/input that demonstrates the bypass)
- Any suggested remediation

## Key Security Controls in This Project

- **SSRF protection** (`lib/security/ssrf.ts`, `lib/net/safeRequest.ts`,
  `services/tls`): every outbound connection to a user-supplied target,
  including each hop of an HTTP redirect chain, is resolved and validated
  against private/loopback/link-local/multicast/reserved address space
  (including cloud metadata endpoints) before the socket is opened. The
  connection is pinned to the validated IP to prevent DNS-rebinding
  time-of-check/time-of-use bypasses.
- **Input validation** (`lib/validation/target.ts`): targets are parsed and
  restricted to `http`/`https` schemes, ports 80/443, and public hostnames
  before any network activity begins.
- **Rate limiting** (`lib/rateLimit.ts`): the analyze endpoint is limited
  per client IP.
- **Timeouts and response caps** (`lib/net/safeRequest.ts`): outbound
  requests enforce connect/read timeouts, a maximum redirect count, and a
  maximum response body size.
- **Secrets handling**: third-party API keys are read from server-side
  environment variables only and are never sent to the client.

## Responsible Use

This tool must only be used against targets you are authorized to assess.

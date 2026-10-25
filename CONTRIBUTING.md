# Contributing

This started as a portfolio project, but issues and pull requests are welcome.

## Getting Started

```bash
git clone https://github.com/mehmet-yuksell/sentinelscope-security.git
cd sentinelscope-security
npm install
cp .env.example .env
npm run dev
```

## Before Opening a Pull Request

```bash
npm run lint
npm run typecheck
npm test
npm run build
```

All four must pass — this is exactly what CI checks on every push to
`main` and every pull request (CI also audits production dependencies).
New behavior should come with tests; tests must not depend on live network
access (see `tests/integration/safe-request.test.ts` for running network
code against a local server).

## Project Conventions

- **Services own their domain.** Each provider integration lives under
  `services/<name>/` and returns a `ProviderResult<T>` — never throw for an
  expected "no data" case (missing API key, provider timeout); return
  `{ status: "unavailable" | "error" | "not_applicable", message }` instead.
- **No fabricated data.** If a provider has nothing to say, say so in the
  UI (`ProviderStatusNotice`) rather than inventing a plausible-looking
  value. See the README's "Real Data Priority" section.
- **All outbound requests to user-supplied targets go through
  `lib/net/safeRequest.ts`** (or `resolveAndAssertPublic` directly), never
  a bare `fetch`/`http.request` — that's what enforces SSRF protection.
- **Keep services small.** A new provider integration should be a new file
  under `services/`, not an addition to an existing one.
- **Commit messages** follow [Conventional Commits](https://www.conventionalcommits.org/)
  (`feat:`, `fix:`, `docs:`, `chore:`), and user-visible changes are noted
  in [CHANGELOG.md](CHANGELOG.md).

## Reporting Security Issues

See [SECURITY.md](SECURITY.md) — please don't open a public issue for a
security vulnerability.

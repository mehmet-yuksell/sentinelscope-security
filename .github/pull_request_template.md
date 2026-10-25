## Summary

<!-- What does this change and why? Link the issue it resolves, e.g. "Closes #12". -->

## Type of change

- [ ] Bug fix
- [ ] New feature or check
- [ ] Refactor / tooling
- [ ] Documentation

## How was this tested?

<!-- New or updated tests, and anything you verified by hand (target analyzed, what you saw). -->

## Checklist

- [ ] `npm run lint`, `npm run typecheck`, `npm test`, and `npm run build` pass locally
- [ ] New behavior is covered by tests that don't depend on live network access
- [ ] Outbound requests to user-supplied targets go through `lib/net/safeRequest.ts` or `resolveAndAssertPublic`
- [ ] Missing data is shown as "Unavailable" / "Not Applicable" — nothing is fabricated
- [ ] No API keys, tokens, or `.env` contents are included
- [ ] User-visible changes are noted under `[Unreleased]` in `CHANGELOG.md`

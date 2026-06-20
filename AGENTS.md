# AGENTS.md — go-protected-resource-metadata

Go library implementing RFC 9728 — OAuth 2.0 Protected Resource Metadata.

## Dependencies

- **Runtime: standard library only, with one exception class.**
  A non-stdlib runtime dependency is acceptable only when (a) it
  implements a validator no reasonable hand-coding could match
  (libphonenumber-class data: country code numbering plan,
  per-country length rules, IDN normalization tables); (b) it is
  well-maintained and widely used in the Go ecosystem; and
  (c) the alternative is the library quietly accepting input the
  spec rejects. Any other runtime dep needs a discussion and a
  justification in the PR description. Default answer is still
  "no" — the bar is "the spec demands data we cannot reasonably
  ship ourselves."
- **Tests: standard library only by default.** Test-only deps
  still need a one-line justification.
- **Build-time tooling: unconstrained.** Generators, linters,
  release tooling, and similar live under `tools/` (separate
  `go.mod`) or are invoked via `go run` with a pinned version;
  they never end up in library users' `go.sum`.
- **`go.mod`**: keep the `module` path stable at
  `github.com/hstern/go-protected-resource-metadata` (no `/vN` suffix for v0.x/v1.x — Go SemVer
  rule). Major-version bumps follow the `go-jose` branch
  pattern.

## Commit messages

Detailed by default: an imperative title (≤72 chars, no trailing period) plus a
body paragraph explaining *why* the change exists — the spec clause honored, the
behavior changed, the bug observed. Reference public RFC sections (§3.1) and
RFC numbers; never reference private trackers. Reserve single-line commits for
genuinely trivial changes (typo, dependency patch bump, initial scaffold).

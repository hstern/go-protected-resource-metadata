# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-06-20

Initial release: a standard-library-only implementation of RFC 9728 OAuth 2.0
Protected Resource Metadata.

### Added

- Typed `Metadata` document covering every §2 parameter, with an open `Extra`
  map for unknown / future-registered members and the §2.1 `name#lang`
  internationalized variants (byte-stable round-trip), `GetExtra` / `SetExtra`
  and `Localized` accessors, and document-structural `Validate` reporting
  `*ValidationError` / `ErrValidation`.
- `WellKnownPath` and `WellKnownRequestPath` for the §3.1 well-known URL and the
  server mount path (the segment is inserted before the resource path).
- Client `Fetch` and `FetchMetadataURL` with the §3.3/§3.4 resource-match
  (anti-mix-up) check and a typed error model (`ErrResourceMismatch`,
  `ErrUnexpectedStatus` / `*HTTPError`, `ErrInvalidResponse`).
- Server `ServeMetadata` and `Metadata.Handler` (GET/HEAD; 405 otherwise) with
  `WithMaxAge` / `WithETag` HTTP caching (§7.10).
- `ChallengeParam` for the §5.1 `resource_metadata` `WWW-Authenticate` parameter.
- `signed_metadata` parse/expose — `ParseSignedMetadata` and
  `SignedMetadata.Apply` (§2.2) — leaving JWS signature verification to the
  caller.
- Spec-derived conformance fixtures driven through both roles.

[0.1.0]: https://github.com/hstern/go-protected-resource-metadata/releases/tag/v0.1.0

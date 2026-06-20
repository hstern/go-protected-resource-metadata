# go-protected-resource-metadata

[![Go Reference](https://pkg.go.dev/badge/github.com/hstern/go-protected-resource-metadata.svg)](https://pkg.go.dev/github.com/hstern/go-protected-resource-metadata)

A typed implementation of **RFC 9728 — OAuth 2.0 Protected Resource Metadata**
(Proposed Standard, 2025-04).
Spec: <https://www.rfc-editor.org/rfc/rfc9728.html>

An OAuth 2.0 protected resource publishes a small JSON document — served at
`/.well-known/oauth-protected-resource` — advertising which authorization
servers it trusts, what scopes it exposes, and how it expects tokens, so a
client can discover how to obtain a usable token without out-of-band
configuration. A `401` can point clients straight at that document through the
`resource_metadata` parameter of a `WWW-Authenticate` challenge.

This library provides the typed metadata document, both halves of the
well-known endpoint (a server side that publishes it and a client side that
fetches and validates it), and a helper for the `resource_metadata` challenge
parameter.

Standard library only. No JOSE, no JWT verification, no framework glue.

> **Status: pre-release, under active development.** The API is taking shape and
> may change before the first `v0.1.0` tag. The package currently exposes
> `SpecVersion`; the `Metadata` document, `WellKnownPath`, `Fetch`, the server
> `Handler`, and `ChallengeParam` land over the phases leading to `v0.1.0`.

## Install

```bash
go get github.com/hstern/go-protected-resource-metadata
```

Requires Go 1.26+.

## Scope

In scope: the typed `Metadata` document (§2) with JSON round-tripping and
open-extension passthrough, the `/.well-known/oauth-protected-resource` URL
construction (§3.1), the client `Fetch` with the §3.3/§3.4 resource-match
validation, the server publish side, and the `resource_metadata` challenge
helper (§5.1).

Out of scope, by design:

- **JWS verification of `signed_metadata`.** The document is parsed and exposed;
  verifying its signature is a JOSE concern for the caller.
- **Authorization Server Metadata (RFC 8414).** This is the *resource* side
  only; the authorization-server document is a separate concern.
- **Token validation and the authorization decision.** Surfacing the advertised
  issuers, scopes, and bearer methods is in scope; deciding whether a given
  token is acceptable is the caller's policy.

## Versioning

Semantic Versioning, tracked independently of the spec. The current series is
pre-`v0.1.0`; the public API may change. The targeted spec version is exposed as
`prm.SpecVersion`.

## License

Apache-2.0 — see [LICENSE](LICENSE).

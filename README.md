# go-protected-resource-metadata

[![Go Reference](https://pkg.go.dev/badge/github.com/hstern/go-protected-resource-metadata.svg)](https://pkg.go.dev/github.com/hstern/go-protected-resource-metadata)

A typed implementation of **RFC 9728 — OAuth 2.0 Protected Resource Metadata**
(Proposed Standard, 2025-04).
Spec: <https://www.rfc-editor.org/rfc/rfc9728.html>

An OAuth 2.0 protected resource publishes a small JSON document — served at
`/.well-known/oauth-protected-resource` — that advertises which authorization
servers it trusts, which scopes it exposes, and how it expects tokens, so a
client (increasingly an AI agent or MCP client) can discover how to obtain a
usable token without out-of-band configuration. A `401` can point clients
straight at that document through the `resource_metadata` parameter of a
`WWW-Authenticate` challenge.

This library provides the typed metadata document, both halves of the well-known
endpoint — a server side that publishes it and a client side that fetches and
validates it — and a helper for the `resource_metadata` challenge parameter.

Standard library only. No JOSE, no JWT signature verification, no framework glue.

## Install

```bash
go get github.com/hstern/go-protected-resource-metadata
```

Requires Go 1.26+. The package is imported as `prm`.

## Server: publish the metadata document

Build a `Metadata`, then mount its `Handler` at the path `WellKnownRequestPath`
returns:

```go
m := &prm.Metadata{
	Resource:               "https://resource.example.com",
	AuthorizationServers:   []string{"https://as.example.com"},
	ScopesSupported:        []string{"profile", "email"},
	BearerMethodsSupported: []string{prm.BearerMethodHeader},
}

path, err := prm.WellKnownRequestPath(m.Resource) // /.well-known/oauth-protected-resource
if err != nil {
	return err
}
mux := http.NewServeMux()
mux.Handle(path, m.Handler(prm.WithMaxAge(time.Hour)))
```

`Handler` validates the document once, serves it as `application/json` to `GET`
and `HEAD` (rejecting other methods with `405`), and supports HTTP caching via
`WithMaxAge` and `WithETag` (an `If-None-Match` match returns `304`). For an
endpoint you already run, `ServeMetadata(w, m)` is the à-la-carte primitive — no
router imposed.

The well-known segment is *inserted* between the host and any path of the
resource identifier (RFC 9728 §3.1), so a resource named
`https://resource.example.com/tenant1` serves at
`/.well-known/oauth-protected-resource/tenant1`. `WellKnownRequestPath` computes
that for you.

## Client: fetch and validate

```go
m, err := prm.Fetch(ctx, http.DefaultClient, "https://resource.example.com")
if err != nil {
	// transport failure, a non-200 status, an undecodable body, or a
	// resource mismatch — see the error model below
	return err
}
// m.AuthorizationServers, m.ScopesSupported, m.BearerMethodsSupported, ...
```

`Fetch` builds the well-known URL, retrieves the document over the `*http.Client`
you pass (TLS and timeouts are its concern), and enforces the RFC 9728 §3.3/§3.4
anti-mix-up check: the document's `resource` must be **identical** to the
identifier you requested, or `Fetch` returns `ErrResourceMismatch` and discards
the document.

```go
switch {
case errors.Is(err, prm.ErrResourceMismatch):
	// the returned resource did not match the requested identifier (§3.4)
case errors.Is(err, prm.ErrUnexpectedStatus):
	var he *prm.HTTPError
	errors.As(err, &he) // he.StatusCode has the exact code
case errors.Is(err, prm.ErrInvalidResponse):
	// a 200 body that would not decode
}
```

When the metadata URL comes from a `WWW-Authenticate` challenge rather than from
constructing the well-known path, use `FetchMetadataURL`, passing the URL you
used to call the resource server as the expected resource (§3.3).

## The `resource_metadata` challenge (§5.1)

`ChallengeParam` returns the bare `(name, value)` pair to add to a
`WWW-Authenticate` challenge you are already building — for example the "extra"
parameters of a bearer-token library — without coupling to it:

```go
name, value := prm.ChallengeParam(metadataURL)
// name == "resource_metadata"; the serializer quotes value:
//   WWW-Authenticate: Bearer resource_metadata="https://.../.well-known/oauth-protected-resource"
```

## Extension and internationalized members

Members beyond the RFC 9728 names — service-specific extensions and the §2.1
`name#lang` internationalized variants — round-trip byte-for-byte through `Extra`
and are read or written with typed accessors:

```go
var feature string
present, err := m.GetExtra("x_example_org_feature", &feature)

name, ok := m.Localized("resource_name", "fr") // tagged variant, untagged fallback
```

## Signed metadata (§2.2)

`signed_metadata` is a JWT (JWS Compact Serialization) that restates the metadata
as signed claims. This library **parses and exposes** it but does not verify the
signature — that is a JOSE concern for the caller:

```go
sm, err := m.ParseSignedMetadata() // (nil, nil) if absent; no signature check
// verify sm.SigningInput / sm.Signature with sm.Header against a key for sm.Issuer,
// then apply the §2.2 precedence:
merged, err := sm.Apply(m)
```

## Scope

In scope: the typed `Metadata` document and `Validate`, the
`/.well-known/oauth-protected-resource` URL construction (client and server
sides), the client `Fetch` with the §3.3/§3.4 resource-match, the server publish
side, the `resource_metadata` challenge helper, and `signed_metadata`
parse/expose with the §2.2 precedence merge.

Out of scope, by design:

- **JWS verification of `signed_metadata`** — parsed and exposed; verifying the
  signature is a JOSE concern.
- **Authorization Server Metadata (RFC 8414)** — this is the *resource* side.
- **Token validation and the authorization decision** — surfacing the advertised
  issuers, scopes, and bearer methods is in scope; deciding whether a token is
  acceptable is the caller's policy.
- **Client-side response caching** — the server `Handler` sets cache headers; the
  client `Fetch` keeps no cache of its own.

## Versioning

Semantic Versioning, tracked independently of the spec. The current series is
`v0.x`: the public API may still change before `v1.0.0`. The targeted spec
version is exposed as `prm.SpecVersion`.

## License

Apache-2.0 — see [LICENSE](LICENSE).

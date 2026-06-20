// Copyright 2026 The go-protected-resource-metadata Authors
// SPDX-License-Identifier: Apache-2.0

// Package prm implements RFC 9728, OAuth 2.0 Protected Resource Metadata: the
// typed metadata document an OAuth 2.0 protected resource publishes about
// itself, its /.well-known/oauth-protected-resource endpoint, and the
// resource_metadata WWW-Authenticate challenge parameter that points clients at
// it.
//
// A protected resource advertises which authorization servers it trusts, what
// scopes it exposes, and how it expects tokens, so a client can discover how to
// obtain a usable token without out-of-band configuration. This package
// provides the typed document with JSON round-tripping, both halves of the
// well-known endpoint — a server side that publishes the document and a client
// side that fetches and validates it — and a helper for the resource_metadata
// challenge parameter.
//
// The library depends only on the standard library. Verifying the JWS signature
// of a signed_metadata document is out of scope: the package parses and exposes
// it, leaving signature verification to the caller and a JOSE library.
//
// Spec: https://www.rfc-editor.org/rfc/rfc9728.html
package prm

// SpecVersion is the version of the specification this package targets.
const SpecVersion = "RFC 9728"

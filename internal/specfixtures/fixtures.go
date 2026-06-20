// Copyright 2026 The go-protected-resource-metadata Authors
// SPDX-License-Identifier: Apache-2.0

// Package specfixtures holds spec-derived conformance vectors for RFC 9728.
//
// RFC 9728 publishes no machine-readable conformance suite and convenes no
// interop event, so these fixtures are derived directly from the specification's
// own examples and its MUST requirements. They are internal: the library's
// conformance tests drive both the server and client roles through them.
package specfixtures

// ValidDocument is a representative, valid RFC 9728 §2 protected resource
// metadata document.
// It carries a §2.1 internationalized "resource_name#fr" variant and a
// service-specific extension member so a round trip exercises the open-Extra
// passthrough, not just the typed fields.
const ValidDocument = `{
  "resource": "https://resource.example.com",
  "authorization_servers": ["https://as1.example.com", "https://as2.example.net"],
  "jwks_uri": "https://resource.example.com/jwks",
  "scopes_supported": ["profile", "email"],
  "bearer_methods_supported": ["header", "body"],
  "resource_signing_alg_values_supported": ["RS256", "ES256"],
  "resource_documentation": "https://resource.example.com/docs",
  "resource_name": "Example Protected Resource",
  "resource_name#fr": "Ressource protégée",
  "x_example_org_feature": "enabled"
}`

// WellKnownCase is a §3.1 well-known URL construction vector: a resource
// identifier and the client-facing metadata URL and server mount path it yields.
type WellKnownCase struct {
	Name        string
	Resource    string
	URL         string // client-facing metadata URL (WellKnownPath)
	RequestPath string // server mount path (WellKnownRequestPath)
}

// WellKnownCases covers the §3.1 examples: no path, a path component (suffix
// inserted before it), and a query component (preserved after the inserted path).
var WellKnownCases = []WellKnownCase{
	{
		Name:        "no path",
		Resource:    "https://resource.example.com",
		URL:         "https://resource.example.com/.well-known/oauth-protected-resource",
		RequestPath: "/.well-known/oauth-protected-resource",
	},
	{
		Name:        "with path",
		Resource:    "https://resource.example.com/resource1",
		URL:         "https://resource.example.com/.well-known/oauth-protected-resource/resource1",
		RequestPath: "/.well-known/oauth-protected-resource/resource1",
	},
	{
		Name:        "with query",
		Resource:    "https://resource.example.com/tenant?id=blue",
		URL:         "https://resource.example.com/.well-known/oauth-protected-resource/tenant?id=blue",
		RequestPath: "/.well-known/oauth-protected-resource/tenant",
	},
}

// Challenge vectors for the §5.1 resource_metadata WWW-Authenticate parameter.
const (
	// ChallengeMetadataURL is the metadata URL a challenge points at.
	ChallengeMetadataURL = "https://resource.example.com/.well-known/oauth-protected-resource"
	// ChallengeHeader is the §5.1 example WWW-Authenticate header value.
	ChallengeHeader = `Bearer resource_metadata="https://resource.example.com/.well-known/oauth-protected-resource"`
)

// MismatchDocument is a well-formed document whose resource is NOT the requested
// identifier — the §3.3/§3.4 anti-mix-up case a client MUST reject.
const MismatchDocument = `{"resource":"https://attacker.example.com"}`

// InvalidDocument is a metadata document that violates a specific §2 MUST.
type InvalidDocument struct {
	Name string
	JSON string
	Why  string
}

// InvalidDocuments has one fixture per document-structural MUST that Validate
// enforces.
var InvalidDocuments = []InvalidDocument{
	{"missing resource", `{"scopes_supported":["profile"]}`, "resource is REQUIRED (§2)"},
	{"non-https resource", `{"resource":"http://resource.example.com"}`, "resource MUST be an https URL (§2)"},
	{"resource with fragment", `{"resource":"https://resource.example.com#x"}`, "resource MUST NOT contain a fragment (§2)"},
	{"bad bearer method", `{"resource":"https://resource.example.com","bearer_methods_supported":["smtp"]}`, "bearer_methods_supported values MUST be header, body, or query (§2)"},
}
